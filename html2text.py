import sys
import json
import fasttext
import trafilatura

model = fasttext.load_model("lid.176.bin")

if len(sys.argv) < 2:
	print("Usage: python script.py <filename>")
	sys.exit(1)

filename = sys.argv[1]

# read your HTML
with open(filename, encoding="utf-8") as f:
	html = f.read()

# extract structured data (JSON with title, text, etc.)
extracted = trafilatura.extract(
	html,
	include_comments=False,
	include_tables=False,
	with_metadata=True,
	favor_recall=True,
	output_format="json"
)

if extracted:
	data = json.loads(extracted)
	text = data.get("text", "").strip()
	title = data.get("title") or filename
	clean_text = " ".join(text.splitlines())

	if clean_text:
		label, prob = model.predict(clean_text)
		lang = label[0].replace("__label__", "")
		output = {
			"title": title,
			"text": text,
			"lang": lang,
			"lang_prob": f"{prob[0]:.3f}",
			"fingerprint": data.get("fingerprint", "")
		}
		print(json.dumps(output, ensure_ascii=False, indent=4))

