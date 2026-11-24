# CaseLink – prototype

Complaint in, investigator-ready case file and gang view out. Built for Rajasthan Police Hackathon 2026, PS01 (Cyber Fraud, Phishing & Malicious Apps).

## What works

- **Text and link triage.** Paste a victim's message. CaseLink extracts URLs, domains, UPI IDs, phone numbers and IPs, then scores each link and the message wording. Every point of the score comes with a stated reason.
- **Trained classifier.** A character n-gram model reads the registered domain name (`sbi-kyc-update.top`) and adds a reason when it looks like a phishing domain. Trained on 20,000 real phishing domains (Phishing.Database) against 20,000 popular domains; on 8,000 held-out domains it reaches AUC 0.905, precision 0.84, recall 0.81 (`app/model/metrics.json`). It supports the rules and never flags official bank domains. Retrain with `python -m scripts.train_model`.
- **Screenshot OCR.** `POST /api/analyze/image` reads a screenshot with Tesseract (English and Hindi if installed), then runs the text through the same pipeline. Small phone screenshots are enlarged first. Tested on generated screenshots.
- **Static APK triage.** Parses real binary-manifest APKs with androguard (package, permissions, signing certificate), flags risky permission combinations, debug-signed apps and brand impersonation, and extracts hardcoded UPI IDs and Telegram bot IDs. The APK is never executed. Tested on a real public sample APK.
- **Gang linking.** Complaints sharing a domain, UPI ID, phone, IP, Telegram bot, APK hash or APK signing certificate are joined into one cluster, with the identifiers shared by the most complaints ranked as the first targets to act on. Shared platforms (bit.ly, telegram.org, wa.me and similar) and the public Android debug certificate are ignored so unrelated cases are not merged.
- **Bulk intake.** Import a CSV (`text`, optional `label`) with up to 5,000 complaints.
- **Live checks (opt-in).** Domain age through RDAP, plus a look at what the page actually asks for: password and OTP fields, brand impersonation, forms posting to another domain, redirect chains. Start the server with `CASELINK_LIVE=1`. Because this fetches addresses supplied by strangers, it is hardened against SSRF: public IPs only (every redirect hop re-checked), the connection pinned to the validated IP, ports 80 and 443 only, no JavaScript, 300 KB cap.
- **Investigator report** (PDF and HTML) and a **dashboard** with a live cluster graph.

## Run it

```bash
pip install -r requirements.txt
sudo apt install tesseract-ocr tesseract-ocr-hin    # for screenshot OCR
uvicorn app.main:app --port 8000                    # add CASELINK_LIVE=1 to enable live checks
# open http://localhost:8000 and click "Load demo data"
pytest -q
```

`GET /api/health` shows which features are active. API docs are at `/docs`.

## Demo script (2 minutes)

1. Click **Load demo data**: 9 synthetic complaints and 2 synthetic APKs.
2. Open cluster `CL-0001`: seven complaints from different victims tied together by one UPI ID, a Telegram bot, a phishing domain, an IP and a phone number.
3. Upload a screenshot of a scam message that mentions `refund.desk77@ybl`. It is read by OCR and joins the cluster instantly.
4. Open the PDF report and show the UPI ID listed as the first account to freeze.

## Honest limits

- **Classifier.** The benign set is popular websites, so the model mostly separates unusual-looking domains from well-known ones. A small legitimate site with an odd name can score high, which is why it is only one signal next to the rules. Retraining on real complaint data from R4C would improve it most.
- **Live checks.** The page-inspection and domain-age logic is tested against a local test site. The real RDAP lookup was **not** verified end to end, because the build sandbox blocks outbound DNS. Test it once on a normal internet connection before the finale. Many scam pages are already taken down by the time they are checked, in which case the report says so and advises preserving evidence.
- **Demo data is invented.** The nine demo complaints and two demo "APKs" are synthetic, and the demo APKs are tiny ZIP files with no code. Real malware is deliberately not shipped with the project. The APK parser itself is tested on a real, benign sample APK; the finale is the place to run it on real samples supplied by organisers.
- **Scale.** SQLite plus a graph rebuilt per request is fine for thousands of complaints; Neo4j would replace it at state scale.

## Layout

```
app/extract.py        identifier extraction
app/url_analyzer.py   phishing link rules + trained-model signal
app/ml.py             classifier features and inference
app/live.py           SSRF-safe domain age and page inspection
app/ocr.py            screenshot OCR
app/apk_analyzer.py   static APK triage (androguard)
app/pipeline.py       text analysis and scoring
app/graph.py          SQLite store and cluster graph
app/report.py         HTML and PDF reports
app/main.py           FastAPI app
app/static/           dashboard
app/model/            trained model and its metrics
scripts/train_model.py  retrain the classifier from public data
tests/                32 tests
```
