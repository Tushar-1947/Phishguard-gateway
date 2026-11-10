import os
from email import policy
from email.parser import BytesParser

import pytest

from phishguard.analyzer import analyze
from phishguard.attachments import analyze_attachments
from phishguard.header_analysis import analyze_headers, root_domain
from phishguard.ml_model import load_model
from phishguard.url_analysis import check_anchor_mismatch, extract_urls, score_url

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def raw(name):
    with open(os.path.join(SAMPLES, name), "rb") as fh:
        return fh.read()


def parse(name):
    return BytesParser(policy=policy.default).parsebytes(raw(name))


def msgs(f):
    return " | ".join(x.message for x in f)


def test_root_domain():
    assert root_domain("mail.google.com") == "google.com"
    assert root_domain("a.b.example.co.uk") == "example.co.uk"
    assert root_domain("185.23.77.9") == "185.23.77.9"


def test_header_detects_spoofing_and_auth_failures():
    text = msgs(analyze_headers(parse("phishing_credential.eml")))
    assert "SPF result: fail" in text and "DMARC result: fail" in text
    assert "impersonates 'paypal'" in text
    assert "Reply-To" in text


def test_header_clean_message_has_no_findings():
    assert analyze_headers(parse("legitimate_meeting.eml")) == []


def test_typosquat_detected():
    from email.message import EmailMessage
    m = EmailMessage()
    m["From"] = "x@paypa1.com"
    m["Message-ID"] = "<1@x>"; m["Date"] = "Mon, 09 Nov 2026 08:15:00 +0000"
    m["Authentication-Results"] = "x; spf=pass; dkim=pass; dmarc=pass"
    assert "typo-squat" in msgs(analyze_headers(m))


def test_url_heuristics():
    assert any("IP address" in f.message for f in score_url("http://10.0.0.5/login"))
    assert any("shortener" in f.message for f in score_url("https://bit.ly/abc"))
    assert any("Punycode" in f.message for f in score_url("https://xn--pypal-4ve.com/"))
    assert score_url("https://docs.example.com/notes") == []


def test_anchor_mismatch():
    urls, anchors = extract_urls("", '<a href="http://evil.top/x">https://www.paypal.com/login</a>')
    assert "http://evil.top/x" in urls
    assert check_anchor_mismatch(anchors)[0].points == 25


def test_attachments():
    info, f = analyze_attachments(parse("phishing_malware_attachment.eml"))
    assert {a["filename"] for a in info} == {"Invoice_4471.pdf.exe", "Statement.xlsm"}
    assert all(len(a["sha256"]) == 64 for a in info)
    text = msgs(f)
    assert "Double extension" in text and "Macro-enabled" in text


@pytest.mark.parametrize("name,expected", [
    ("legitimate_meeting.eml", "clean"),
    ("bec_ceo_fraud.eml", "suspicious"),
    ("phishing_credential.eml", "malicious"),
    ("phishing_malware_attachment.eml", "malicious"),
])
def test_end_to_end_verdicts(name, expected):
    assert analyze(raw(name), model=load_model()).verdict == expected


def test_rules_only_still_flags_obvious_phish():
    # Works without the ML model
    assert analyze(raw("phishing_credential.eml"), model=None).verdict == "malicious"
    assert analyze(raw("legitimate_meeting.eml"), model=None).verdict == "clean"
