"""Orchestrates all detection modules and produces a final verdict."""
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Optional

from .attachments import analyze_attachments
from .dns_checks import live_dns_checks, verify_dkim
from .header_analysis import analyze_headers, domain_of
from .models import Finding, Report
from .url_analysis import analyze_urls

SUSPICIOUS_THRESHOLD = 35
MALICIOUS_THRESHOLD = 65
ML_MAX_POINTS = 40
URL_CAP, HEADER_CAP, ATTACH_CAP = 60, 50, 60


def _bodies(msg):
    text = html = ""
    for part in msg.walk():
        if part.is_multipart() or part.get_filename():
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:
            continue
        if ctype == "text/plain":
            text += content + "\n"
        elif ctype == "text/html":
            html += content + "\n"
    return text, html


def _html_to_text(html: str) -> str:
    import re
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def _cap(findings, cap):
    """Cap a module's total contribution while keeping every finding visible."""
    total = sum(f.points for f in findings)
    if total <= cap:
        return findings
    scale = cap / total
    return [Finding(f.module, f.message, max(1, round(f.points * scale))) for f in findings]


def analyze(raw: bytes, model=None, live_dns: bool = False, verify_dkim_sig: bool = False,
            vt_key: str = "") -> Report:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    text, html = _bodies(msg)
    subject = str(msg.get("Subject", ""))
    _, from_addr = parseaddr(str(msg.get("From", "")))

    findings = analyze_headers(msg)
    if live_dns:
        findings += live_dns_checks(domain_of(from_addr))
    if verify_dkim_sig:
        findings += verify_dkim(raw)
    header_f = _cap(findings, HEADER_CAP)

    urls, url_f = analyze_urls(text, html, vt_key)
    url_f = _cap(url_f, URL_CAP)

    att_info, att_f = analyze_attachments(msg)
    att_f = _cap(att_f, ATTACH_CAP)

    all_f = header_f + url_f + att_f

    prob = None
    if model is not None:
        prob = model.predict_proba(f"{subject}\n{text or _html_to_text(html)}")
        pts = round(prob * ML_MAX_POINTS)
        if pts >= 8:
            all_f.append(Finding("ml", f"ML classifier: {prob:.0%} phishing probability", pts))

    score = min(100, sum(f.points for f in all_f))
    verdict = "malicious" if score >= MALICIOUS_THRESHOLD else "suspicious" if score >= SUSPICIOUS_THRESHOLD else "clean"
    all_f.sort(key=lambda x: -x.points)
    return Report(score=score, verdict=verdict, ml_probability=prob, subject=subject,
                  sender=from_addr, findings=all_f, urls=urls, attachments=att_info)


def format_report(r: Report) -> str:
    icon = {"clean": "[ OK ]", "suspicious": "[WARN]", "malicious": "[BLOCK]"}[r.verdict]
    lines = [f"{icon} verdict={r.verdict.upper()}  risk={r.score}/100",
             f"  From   : {r.sender}", f"  Subject: {r.subject}"]
    if r.ml_probability is not None:
        lines.append(f"  ML P(phish): {r.ml_probability:.2f}")
    if r.findings:
        lines.append("  Findings:")
        lines += [f"    +{f.points:<3} [{f.module}] {f.message}" for f in r.findings]
    if r.attachments:
        lines.append("  Attachments:")
        lines += [f"    {a['filename']} ({a['size']} B) sha256={a['sha256'][:16]}..." for a in r.attachments]
    return "\n".join(lines)
