
use anyhow::Result;
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write, Seek, SeekFrom};
use std::env;
use std::error::Error;
use std::fs::{File, write, remove_file};
use tokio::time::{sleep, Duration};
use flate2::read::GzDecoder;
use std::collections::HashMap;
use url::Url;
use readability_rust::{Readability, ReadabilityOptions};
use std::time::{SystemTime, UNIX_EPOCH};
use std::process::{Command, Stdio};


#[derive(Debug, Deserialize)]
struct CcRecord {
	url: String,
	filename: String,

	#[serde(deserialize_with = "de_from_str")]
	offset: u64,

	#[serde(deserialize_with = "de_from_str")]
	length: u64,
}

#[derive(Debug)]
struct DomainRecord {
	harmonicc_pos: usize,
	harmonicc_val: f64,
	pr_pos: usize,
	pr_val: f64,
	host: String,
	n_hosts: usize,
}

/// Extracts the domain (first subdomain + TLD) from a URL.
/// Example: "https://news.google.com" -> "google.com"
pub fn extract_domain(url_str: &str) -> Option<String> {
	let parsed = Url::parse(url_str).ok()?;
	let host = parsed.host_str()?;

	// Split host by '.' and collect
	let parts: Vec<&str> = host.split('.').collect();

	// Handle short or weird hostnames safely
	if parts.len() < 2 {
		return Some(host.to_string());
	}

	// Handle common multi-level TLDs like .co.uk, .com.au, etc.
	let multi_tlds = ["co.uk", "org.uk", "gov.uk", "com.au", "co.jp"];
	let last_two = parts[parts.len() - 2..].join(".");

	if multi_tlds.contains(&last_two.as_str()) && parts.len() >= 3 {
		// example.co.uk → take first subdomain + 2-part TLD → example.co.uk
		let domain = parts[parts.len() - 3..].join(".");
		return Some(domain);
	}

	// Default case → take last two segments (domain + TLD)
	let domain = parts[parts.len() - 2..].join(".");
	Some(domain)
}

fn reverse_domain(host_rev: &str) -> String {
	let parts: Vec<&str> = host_rev.split('.').collect();
	let reversed_parts: Vec<&str> = parts.into_iter().rev().collect();
	reversed_parts.join(".")
}

fn read_se_domains(path: &str) -> Result<Vec<DomainRecord>, Box<dyn Error>> {
	let file = File::open(path)?;
	let reader = BufReader::new(file);

	let mut results: Vec<DomainRecord> = Vec::new();

	for (line_no, line_res) in reader.lines().enumerate() {
		let line = line_res?;
		let line = line.trim();

		// skip empty lines and header/comment lines that start with '#'
		if line.is_empty() || line.starts_with('#') {
			continue;
		}

		// split on whitespace
		let cols: Vec<&str> = line.split_whitespace().collect();
		if cols.len() < 6 {
			eprintln!("warning: skipping malformed line {} (expected >=6 cols): {:?}", line_no + 1, line);
			continue;
		}

		// parse fields (we expect at least 6 columns)
		let harmonicc_pos = match cols[0].parse::<usize>() {
			Ok(v) => v,
			Err(_) => {
				eprintln!("warning: could not parse harmonicc_pos on line {}: {:?}", line_no + 1, cols[0]);
				continue;
			}
		};

		let harmonicc_val = match cols[1].parse::<f64>() {
			Ok(v) => v,
			Err(_) => {
				eprintln!("warning: could not parse harmonicc_val on line {}: {:?}", line_no + 1, cols[1]);
				continue;
			}
		};

		let pr_pos = match cols[2].parse::<usize>() {
			Ok(v) => v,
			Err(_) => {
				eprintln!("warning: could not parse pr_pos on line {}: {:?}", line_no + 1, cols[2]);
				continue;
			}
		};

		let pr_val = match cols[3].parse::<f64>() {
			Ok(v) => v,
			Err(_) => {
				eprintln!("warning: could not parse pr_val on line {}: {:?}", line_no + 1, cols[3]);
				continue;
			}
		};

		let host_rev = cols[4].to_string();

		let n_hosts = match cols[5].parse::<usize>() {
			Ok(v) => v,
			Err(_) => {
				eprintln!("warning: could not parse n_hosts on line {}: {:?}", line_no + 1, cols[5]);
				continue;
			}
		};

		// filter .se domains (host_rev ending with ".se")
		if host_rev.starts_with("se.") {
			results.push(DomainRecord {
				harmonicc_pos,
				harmonicc_val,
				pr_pos,
				pr_val,
				host: reverse_domain(&host_rev),
				n_hosts,
			});
		}
	}

	Ok(results)
}

/// Write the filtered `.se` domains to a new file in the same format.
fn write_se_domains(path: &str, records: &[DomainRecord]) -> Result<(), Box<dyn Error>> {
	let mut file = File::create(path)?;

	// optional header (comment line like the source file)
	writeln!(
		file,
		"#harmonicc_pos\t#harmonicc_val\t#pr_pos\t#pr_val\t#host\t#n_hosts"
	)?;

	for rec in records {
		writeln!(
			file,
			"{}\t{:.7E}\t{}\t{:.18}\t{}\t{}",
			rec.harmonicc_pos,
			rec.harmonicc_val,
			rec.pr_pos,
			rec.pr_val,
			reverse_domain(&rec.host),
			rec.n_hosts
		)?;
	}

	Ok(())
}

fn records_to_map(records: &[DomainRecord]) -> HashMap<String, &DomainRecord> {
	let mut map = HashMap::new();
	for rec in records {
		map.insert(rec.host.clone(), rec);
	}
	return map;
}

fn de_from_str<'de, D>(deserializer: D) -> Result<u64, D::Error> where D: serde::Deserializer<'de> {
	let s = String::deserialize(deserializer)?;
	s.parse::<u64>().map_err(serde::de::Error::custom)
}

fn build_index_url(cc_crawl: &String) -> String {
	format!(
		"https://index.commoncrawl.org/{}-index?url=*.se/*&output=json",
		cc_crawl
	)
}

fn build_output_file(cc_crawl: &String) -> String {
	format!(
		"/mnt/data_ssd/{}.warc",
		cc_crawl
	)
}

async fn fetch_and_write(client: &reqwest::Client, rec: &CcRecord, writer: &mut std::io::BufWriter<std::fs::File>) -> anyhow::Result<()> {
	let offset = rec.offset;
	let length = rec.length;
	let range = format!("bytes={}-{}", offset, offset + length - 1);
	let warc_url = format!("https://data.commoncrawl.org/{}", rec.filename);

	let resp = client.get(&warc_url).header("Range", range).send().await?;
	if !resp.status().is_success() {
		eprintln!("[WARN] Skipping {} (HTTP {})", warc_url, resp.status());
		eprintln!("sleeping a bit before continuing.");
		sleep(Duration::from_millis(1000)).await;
		return Ok(());
	}

	let bytes = resp.bytes().await?;
	let mut gz = GzDecoder::new(&bytes[..]);

	let mut decompressed = Vec::new();
	gz.read_to_end(&mut decompressed)?; // decompress fully into memory

	writer.write_all(&decompressed)?;
	writer.flush()?;

	println!("[OK] Wrote uncompressed WARC for {}", rec.url);
	Ok(())
}

fn parse() -> Result<(), Box<dyn std::error::Error>> {

	let html = fs::read_to_string("ww2.html")?;
	let base_url = Url::parse("https://en.wikipedia.org/wiki/World_War_II")?;

	// set up readability options (you can tweak these)
	let options = ReadabilityOptions {
		..Default::default()
	};

	// parse article
	let mut readability = Readability::new(&html, Some(options))?;
	if let Some(article) = readability.parse() {
		println!("Title: {}", article.title.unwrap());
		println!("\nPlain text:\n{}\n", article.text_content.unwrap());
	} else {
		println!("❌ No article content extracted.");
	}

	return Ok(());
}

fn read_warc_headers(file_path: &str) -> io::Result<()> {
	let mut file = File::open(file_path)?;
	let mut reader = BufReader::new(&file);

	// create unique tmp filename
	let unique_id = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_nanos();
	let tmp_path = format!("/tmp/warc_{}.html", unique_id);

	let out_path = format!("{}.json", file_path);
	let mut out_file = OpenOptions::new()
		.create(true)
		.append(true)
		.open(&out_path)?;

	loop {
		let mut headers = Vec::new();
		let mut line = String::new();

		// Read header lines until we hit an empty line
		loop {
			line.clear();
			let bytes = reader.read_line(&mut line)?;
			if bytes == 0 {
				// EOF
				remove_file(&tmp_path);
				return Ok(());
			}
			if line.trim().is_empty() {
				break;
			}
			headers.push(line.trim_end().to_string());
		}

		if headers.is_empty() {
			break;
		}

		// Extract Content-Length if present
		let mut content_length = 0usize;
		for h in &headers {
			if let Some(value) = h.strip_prefix("Content-Length: ") {
				content_length = value.parse::<usize>().unwrap_or(0);
			}
		}

		if content_length > 0 {
			// Skip the content body
			let mut content = vec![0u8; content_length + 4];
			reader.read_exact(&mut content)?;

			write(&tmp_path, &content)?;

			// run python script
			let output = Command::new("python3")
				.arg("html2text.py")
				.arg(&tmp_path)
				.stdout(Stdio::piped())
				.stderr(Stdio::null())
				.output()?;

			if output.status.success() {
				let json_output = String::from_utf8_lossy(&output.stdout);

				// parse json
				if let Ok(parsed) = serde_json::from_str::<Value>(&json_output) {
					let lang = parsed.get("lang").and_then(Value::as_str).unwrap_or("");
					let lang_prob = parsed.get("lang_prob").and_then(Value::as_str)
						.and_then(|s| s.parse::<f64>().ok())
						.unwrap_or(0.0);
					let text = parsed.get("text").and_then(Value::as_str).unwrap_or("");

					if lang == "sv" && lang_prob > 0.8 && text.len() > 100 {
						let compact = serde_json::to_string(&parsed)?;
						writeln!(out_file, "{}", compact)?;
						println!("Wrote to output");
					}
				}
			}
		}
	}
	remove_file(&tmp_path);
	return Ok(());
}

#[tokio::main]
async fn main() -> Result<()> {

	let file_path = "/mnt/data_ssd/CC-MAIN-2013-20.warc";
	read_warc_headers(file_path);
	return Ok(());

	parse();
	return Ok(());


	let path = "se_domains.txt";
	let se_domains = read_se_domains(path).unwrap();
	let se_map = records_to_map(&se_domains);

	let args: Vec<String> = env::args().collect();

	if args.len() < 2 {
		eprintln!("Usage: {} <argument>", args[0]);
		return Ok(());
	}

	let cc_crawl = &args[1];

	let client = Client::builder()
		.user_agent("CommonCrawlResearchBot/1.0 (contact: josefcullhed@gmail.com)")
		.build()?;
	println!("[INFO] Querying Common Crawl index: {}", build_index_url(cc_crawl));

	let resp = client.get(build_index_url(cc_crawl)).send().await?;
	let text = resp.text().await?;
	let mut records = Vec::new();

	for line in text.lines() {
		if let Ok(rec) = serde_json::from_str::<CcRecord>(line) {
			records.push(rec);
		} else {
			println!("ERROR");
			return Ok(());
		}
	}

	println!("[INFO] Found {} .se records", records.len());

	let file = OpenOptions::new()
		.create(true)
		.append(true)
		.open(build_output_file(cc_crawl))?;

	let mut writer = std::io::BufWriter::new(file);

	for rec in records {
		if let Some(domain) = extract_domain(&rec.url) {
			if let Some(record) = se_map.get(&domain) {
				if let Err(e) = fetch_and_write(&client, &rec, &mut writer).await {
					eprintln!("[WARN] {} -> {}", rec.url, e);
				}
			} else {
				println!("skipped {}", rec.url);
			}
		} else {
		}
	}

	println!("[DONE] Saved raw WARC records to {}", build_output_file(cc_crawl));
	Ok(())
}
