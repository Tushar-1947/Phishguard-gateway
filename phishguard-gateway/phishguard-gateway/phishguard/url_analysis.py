"""URL extraction, heuristic scoring and optional VirusTotal reputation lookups."""
import base64
import json
import re
import urllib.error
import urllib.request
from html.parser import HTMLParser
from typing import List, Tuple
from urllib.parse import urlparse

from .header_analysis import BRANDS, root_domain
from .models import Finding

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"}
SUSPICIOUS_TLDS = {"zip", "top", "xyz", "click", "tk", "ml", "ga", "cf", "gq", "work", "support", "country", "icu", "live"}
LURE_WORDS = ("login", "signin", "verify", "update", "secure", "account", "password", "confirm", "banking", "wallet", "suspend")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class _AnchorParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.anchors: List[Tuple[str, str]] = []
        self._href = None
        self._text: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._text).strip()))
            self._href = None


def extract_urls(text: str, html: str = "") -> Tuple[List[str], List[Tuple[str, str]]]:
    """Return (unique urls, anchors[(href, visible_text)])."""
    anchors: List[Tuple[str, str]] = []
    if html:
        p = _AnchorParser()
        try:
            p.feed(html)
        except Exception:
            pass
        anchors = p.anchors
    found = URL_RE.findall(text or "") + URL_RE.findall(html or "")
    found += [h for h, _ in anchors if h and h.lower().startswith("http")]
    seen, ordered = set(), []
    for u in found:
        u = u.rstrip(".,;")
        if u not in seen:
            seen.add(u)
            ordered.append(u)
    return ordered, anchors


def score_url(url: str) -> List[Finding]:
    f: List[Finding] = []
    try:
        p = urlparse(url)
    except ValueError:
        return [Finding("url", f"Malformed URL: {url[:60]}", 5)]
    host = (p.hostname or "").lower()
    if not host:
        return f
    short = url if len(url) < 70 else url[:67] + "..."

    if IP_RE.match(host):
        f.append(Finding("url", f"IP address used as host: {short}", 20))
    if "@" in p.netloc:
        f.append(Finding("url", f"Credentials/@ trick in URL: {short}", 15))
    if "xn--" in host:
        f.append(Finding("url", f"Punycode host (possible homograph): {host}", 15))
    if host in SHORTENERS:
        f.append(Finding("url", f"URL shortener hides destination: {host}", 10))
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        f.append(Finding("url", f"High-abuse TLD .{tld}: {host}", 8))
    if host.count(".") >= 4:
        f.append(Finding("url", f"Excessive subdomains: {host}", 8))
    if host.count("-") >= 3:
        f.append(Finding("url", f"Many hyphens in host: {host}", 6))
    if len(url) > 120:
        f.append(Finding("url", "Very long URL (>120 chars)", 5))
    if p.scheme == "http":
        f.append(Finding("url", f"Unencrypted HTTP link: {short}", 5))

    rd = root_domain(host)
    for brand, legit in BRANDS.items():
        if brand in host and rd not in legit:
            f.append(Finding("url", f"Brand '{brand}' used in non-official domain: {host}", 15))
            break
    if any(w in (p.path + "?" + p.query).lower() for w in LURE_WORDS) and not any(rd in l for l in BRANDS.values()):
        f.append(Finding("url", f"Credential-lure keyword in path: {short}", 6))
    return f


def check_anchor_mismatch(anchors: List[Tuple[str, str]]) -> List[Finding]:
    """Flag links whose visible text shows one domain but href goes to another."""
    f: List[Finding] = []
    for href, text in anchors:
        if not href or not href.lower().startswith("http"):
            continue
        m = re.search(r"(?:https?://)?((?:[\w-]+\.)+[a-z]{2,})", text, re.I)
        if not m:
            continue
        shown = root_domain(m.group(1).lower())
        actual = root_domain((urlparse(href).hostname or "").lower())
        if shown and actual and shown != actual:
            f.append(Finding("url", f"Link text shows '{shown}' but points to '{actual}'", 25))
    return f


def virustotal_lookup(url: str, api_key: str, timeout: int = 8) -> List[Finding]:
    """Query VirusTotal v3 for an existing URL report (does not submit the URL)."""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": api_key}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            stats = json.load(r)["data"]["attributes"]["last_analysis_stats"]
    except (urllib.error.URLError, KeyError, ValueError, TimeoutError):
        return []
    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
    if mal >= 3:
        return [Finding("url", f"VirusTotal: {mal} engines flag {url[:60]} as malicious", 45)]
    if mal or sus:
        return [Finding("url", f"VirusTotal: {mal} malicious / {sus} suspicious detections for {url[:60]}", 20)]
    return []


def analyze_urls(text: str, html: str, vt_key: str = "", vt_limit: int = 5):
    urls, anchors = extract_urls(text, html)
    findings: List[Finding] = []
    for u in urls:
        findings.extend(score_url(u))
    findings.extend(check_anchor_mismatch(anchors))
    if vt_key:
        for u in urls[:vt_limit]:
            findings.extend(virustotal_lookup(u, vt_key))
    return urls, findings
