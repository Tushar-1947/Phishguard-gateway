# 🛡️ PhishGuard – Email Security Gateway with Phishing Detection

An SMTP gateway that inspects inbound email and **blocks, quarantines, tags or relays** it based on
header analysis, SPF/DKIM/DMARC checks, URL scanning, attachment inspection and an
ML (scikit-learn) phishing classifier. Every decision is explainable: the report lists each finding and its risk points.

![python](https://img.shields.io/badge/python-3.10%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green) ![tests](https://img.shields.io/badge/tests-15%20passing-brightgreen)

## Features
- **Header & authentication analysis** – SPF / DKIM / DMARC results, Return-Path / Reply-To mismatch, display-name spoofing, brand look-alike & typo-squat sender domains (`paypa1.com`), punycode.
- **Live checks (optional)** – SPF & DMARC DNS policy lookup (`--live-dns`) and cryptographic DKIM verification (`--verify-dkim`).
- **URL scanning** – IP hosts, shorteners, high-abuse TLDs, `@` tricks, homograph domains, and *link-text ≠ real destination* detection; optional **VirusTotal** reputation (`--vt`).
- **Attachment inspection** – executables, double extensions (`invoice.pdf.exe`), macro-enabled Office files, archives, RTL-override filenames, SHA-256 hashing.
- **ML classifier** – TF-IDF word + character n-grams → Logistic Regression; retrainable on your own data.
- **Real SMTP gateway** – built on `aiosmtpd`; rejects (`550`), quarantines, tags (`[SUSPECTED PHISH]`, `X-PhishGuard-*` headers) and relays to a downstream MTA.
- **CLI, JSON output, tests, CI** – exit codes (0 clean / 1 suspicious / 2 malicious) make it scriptable.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the pipeline diagram and scoring design.

## Quick start
```bash
git clone https://github.com/<Tushar-1947>/phishguard-gateway.git
cd phishguard-gateway
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m phishguard gen-data      # create demo training data
python -m phishguard train         # train + save model to models/
pytest -q                          # run the test-suite
```
(A pre-trained demo model is already included in `models/`.)

### Scan emails
```bash
python -m phishguard scan samples/*.eml
python -m phishguard scan samples/phishing_credential.eml --json
python -m phishguard scan mail.eml --live-dns --verify-dkim     # needs internet/DNS
VT_API_KEY=xxxx python -m phishguard scan mail.eml --vt         # VirusTotal lookups
```
Example output:
```
[BLOCK] verdict=MALICIOUS  risk=100/100
  From   : service@paypa1-secure-login.top
  Findings:
    +39  [ml] ML classifier: 97% phishing probability
    +25  [url] Link text shows 'paypal.com' but points to '185.23.77.9'
    +20  [url] IP address used as host: http://185.23.77.9/paypal/login/verify
    +13  [auth] DMARC result: fail
    ...
```

### Run as a gateway
```bash
python -m phishguard serve --port 8025 --relay 127.0.0.1:1025    # relay clean mail downstream
# in another terminal:
python scripts/send_test_mail.py samples/phishing_credential.eml        # -> REJECTED 550
python scripts/send_test_mail.py samples/legitimate_meeting.eml         # -> ACCEPTED
```
Tip: a harmless local sink for the relay is `python -m aiosmtpd -n -l 127.0.0.1:1025`.
Rejected mail is saved to `quarantine/` (`.eml` + `.json` report); all decisions are logged to `logs/gateway.jsonl`.
In production, point your MX / upstream MTA (Postfix `content_filter`, Exim, etc.) at the gateway.

## Scoring
| Score | Verdict | Action |
|---|---|---|
| 0–34 | clean | headers added, relayed |
| 35–64 | suspicious | subject tagged `[SUSPECTED PHISH]`, relayed, copy quarantined |
| 65–100 | malicious | `550` reject + quarantine |

## Project layout
```
phishguard/   header_analysis · dns_checks · url_analysis · attachments · ml_model · dataset · analyzer · gateway · cli
tests/        unit + end-to-end SMTP tests (15)
samples/      4 demo .eml files (credential phish, malware attachment, CEO fraud, legitimate)
models/       trained model + metrics.json
data/         generated training CSV
docs/         architecture
```

## ⚠️ Honest evaluation notes
- The bundled model is trained on a **synthetic, template-generated** corpus so the project runs out-of-the-box. It reaches 100 % on its own held-out split **because the templates are easy to separate – this number does not predict real-world accuracy.**
- For realistic performance retrain on real data (CSV with `text,label` columns, 1 = phishing):
  [Nazario phishing corpus](https://monkey.org/~jose/phishing/), [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/), [Enron emails](https://www.cs.cmu.edu/~enron/) (legitimate) – then `python -m phishguard train --data real.csv`.
- Rule-based layers are heuristics and will produce some false positives/negatives; tune weights/thresholds in `analyzer.py`.
- SPF/DKIM/DMARC from `Authentication-Results` are only trustworthy if stamped by *your* upstream MTA; use `--live-dns/--verify-dkim` for independent checks.

## Ethical use
Sample emails are fabricated and point to non-routable/test destinations. Do not use this repository's samples to attack others. Use the gateway only on mail you are authorised to inspect.

## Roadmap
Web dashboard for quarantine review · sandbox detonation of attachments · BERT-based classifier · DMARC aggregate-report ingestion · Docker image.

## License
MIT
