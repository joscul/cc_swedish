use anyhow::Result;
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde::Deserialize;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use tokio::time::{sleep, Duration};
use flate2::read::GzDecoder;

#[derive(Debug, Deserialize)]
struct CcRecord {
	url: String,
	filename: String,

	#[serde(deserialize_with = "de_from_str")]
	offset: u64,

	#[serde(deserialize_with = "de_from_str")]
	length: u64,
}

fn de_from_str<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;
	s.parse::<u64>().map_err(serde::de::Error::custom)
}

const CC_CRAWL: &str = "CC-MAIN-2025-38";
fn build_index_url() -> String {
	format!(
		"https://index.commoncrawl.org/{}-index?url=*.se/*&output=json",
		CC_CRAWL
	)
}

const OUTPUT_FILE: &str = "swedish_raw.warc";
const DELAY_MS: u64 = 1000; // delay between requests

#[tokio::main]
async fn main() -> Result<()> {
	let client = Client::builder().build()?;
	println!("[INFO] Querying Common Crawl index: {}", build_index_url());

	let resp = client.get(build_index_url()).send().await?;
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
		.open(OUTPUT_FILE)?;

	let mut writer = std::io::BufWriter::new(file);

	for rec in records {
		if let Err(e) = fetch_and_write(&client, &rec, &mut writer).await {
			eprintln!("[WARN] {} -> {}", rec.url, e);
		}
	}

	println!("[DONE] Saved raw WARC records to {}", OUTPUT_FILE);
	Ok(())
}

async fn fetch_and_write(
	client: &reqwest::Client,
	rec: &CcRecord,
	writer: &mut std::io::BufWriter<std::fs::File>,
) -> anyhow::Result<()> {
	let offset = rec.offset;
	let length = rec.length;
	let range = format!("bytes={}-{}", offset, offset + length - 1);
	let warc_url = format!("https://data.commoncrawl.org/{}", rec.filename);

	let resp = client.get(&warc_url).header("Range", range).send().await?;
	if !resp.status().is_success() {
		eprintln!("[WARN] Skipping {} (HTTP {})", rec.url, resp.status());
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
