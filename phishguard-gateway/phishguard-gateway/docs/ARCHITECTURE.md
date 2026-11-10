# Architecture

```
            ┌────────────┐   SMTP    ┌──────────────────────────────────────┐   SMTP   ┌────────────┐
 Sender ───▶│  Internet  │──────────▶│            PhishGuard Gateway        │─────────▶│ Real MTA / │
            └────────────┘           │  (aiosmtpd handler: handle_DATA)     │  relay   │  mailbox   │
                                     └───────────────┬──────────────────────┘          └────────────┘
                                                     │ raw RFC-822 bytes
                                                     ▼
                                     ┌──────────────────────────────────────┐
                                     │            analyzer.analyze()        │
                                     └──┬────────┬─────────┬────────┬───────┘
                                        ▼        ▼         ▼        ▼
                                  header_      url_      attach-   ml_model
                                  analysis   analysis    ments     (TF-IDF+LR)
                                  dns_checks (+VirusTotal)
                                        └────────┴────┬────┴────────┘
                                                      ▼
                                          weighted score 0-100
                                   clean (<35) / suspicious (35-64) / malicious (>=65)
                                                      ▼
                       malicious → 550 reject + quarantine/*.eml,*.json
                       suspicious → tag subject + X-PhishGuard-* headers, relay, copy to quarantine
                       clean      → add X-PhishGuard-* headers, relay
```

## Detection layers

| Layer | Module | What it checks | Max contribution |
|---|---|---|---|
| Header / auth | `header_analysis.py`, `dns_checks.py` | SPF/DKIM/DMARC verdicts, Return-Path & Reply-To mismatch, display-name spoofing, brand look-alike / typo-squat domains, punycode, missing Message-ID/Date; optional live SPF/DMARC DNS lookups and real DKIM signature verification | 50 |
| URLs | `url_analysis.py` | IP hosts, `@` tricks, punycode, shorteners, high-abuse TLDs, subdomain depth, brand-in-wrong-domain, lure keywords, **link text vs. href mismatch**, optional VirusTotal v3 reputation | 60 |
| Attachments | `attachments.py` | executables/scripts, double extensions (`invoice.pdf.exe`), macro Office files, archives, RTL-override names, SHA-256 hashes | 60 |
| ML | `ml_model.py` | TF-IDF (word 1-2grams + char 3-5grams) → Logistic Regression on subject+body | 40 |

Each rule-based module's total is capped so no single layer can dominate; all individual findings remain
visible in the report for explainability. The final score is `min(100, sum of points)`.

## Design decisions
* **Explainable first**: every point added has a human-readable reason; the ML model is one signal, not the verdict.
* **Works offline**: DNS and VirusTotal checks are opt-in flags; rules + ML run with no network.
* **Fail-open on relay problems**: a downstream relay error returns `451` (temporary) so the sending MTA retries.
* **Message integrity**: original bytes are quarantined untouched for forensics.

## Mapping to the internship brief
| Requirement | Where |
|---|---|
| Header analysis | `header_analysis.py` |
| URL scanning | `url_analysis.py` |
| ML-based classification | `ml_model.py`, `dataset.py` |
| VirusTotal API | `url_analysis.virustotal_lookup` (`--vt`, `VT_API_KEY`) |
| SPF / DKIM / DMARC | `header_analysis.parse_auth_results`, `dns_checks.py` |
| Python, Scikit-learn | whole project |
