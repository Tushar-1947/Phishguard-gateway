"""Email header analysis: SPF/DKIM/DMARC results, spoofing and impersonation checks."""
import re
from email.utils import parseaddr
from typing import List

from .models import Finding

# Brand -> legitimate root domains (used for display-name / look-alike detection)
BRANDS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "office.com", "outlook.com", "live.com"},
    "google": {"google.com", "gmail.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"},
    "linkedin": {"linkedin.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "sbi": {"sbi.co.in", "onlinesbi.com"},
    "hdfc": {"hdfcbank.com", "hdfcbank.net"},
    "icici": {"icicibank.com"},
}

_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac"}
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a"})


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip("> ") if "@" in addr else ""


def root_domain(domain: str) -> str:
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain or ""):
        return domain  # IP literal - keep whole
    parts = [p for p in domain.split(".") if p]
    if len(parts) <= 2:
        return domain
    if len(parts[-1]) == 2 and parts[-2] in _SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def parse_auth_results(msg) -> dict:
    """Extract spf/dkim/dmarc verdicts from Authentication-Results / Received-SPF."""
    results = {}
    for hdr in msg.get_all("Authentication-Results", []):
        for mech, verdict in re.findall(r"\b(spf|dkim|dmarc)=(\w+)", str(hdr), re.I):
            results.setdefault(mech.lower(), verdict.lower())
    rspf = msg.get("Received-SPF")
    if rspf and "spf" not in results:
        results["spf"] = str(rspf).strip().split()[0].lower()
    return results


def analyze_headers(msg) -> List[Finding]:
    f: List[Finding] = []

    # --- SPF / DKIM / DMARC as stamped by the upstream MTA ----------------
    auth = parse_auth_results(msg)
    weights = {
        "spf": {"fail": 15, "softfail": 8, "permerror": 5, "none": 3},
        "dkim": {"fail": 10, "permerror": 5, "none": 3},
        "dmarc": {"fail": 20, "permerror": 5, "none": 3},
    }
    for mech, verdict in auth.items():
        pts = weights[mech].get(verdict, 0)
        if pts:
            f.append(Finding("auth", f"{mech.upper()} result: {verdict}", pts))
    if not auth:
        f.append(Finding("auth", "No authentication results present in headers", 4))

    # --- Address consistency ---------------------------------------------
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_dom = domain_of(from_addr)
    if not from_addr:
        f.append(Finding("header", "Missing or malformed From address", 10))
        return f

    _, rp = parseaddr(str(msg.get("Return-Path", "")))
    if rp and root_domain(domain_of(rp)) != root_domain(from_dom):
        f.append(Finding("header", f"Return-Path domain ({domain_of(rp)}) differs from From domain ({from_dom})", 8))

    _, reply = parseaddr(str(msg.get("Reply-To", "")))
    if reply and root_domain(domain_of(reply)) != root_domain(from_dom):
        f.append(Finding("header", f"Reply-To domain ({domain_of(reply)}) differs from From domain ({from_dom})", 12))

    # --- Display-name spoofing -------------------------------------------
    name_l = from_name.lower()
    m = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", from_name)
    if m and root_domain(m.group(1).lower()) != root_domain(from_dom):
        f.append(Finding("header", "Display name contains a different email address than the real sender", 18))

    for brand, legit in BRANDS.items():
        if root_domain(from_dom) in legit:
            continue
        raw_host = from_dom.split(".")[0] if from_dom else ""
        if brand in name_l:
            f.append(Finding("header", f"Display name impersonates '{brand}' but sender domain is {from_dom}", 15))
            break
        if brand in raw_host:
            f.append(Finding("header", f"Sender domain {from_dom} embeds brand '{brand}' (look-alike)", 15))
            break
        if brand in raw_host.translate(_LEET) or brand in raw_host.replace("rn", "m"):
            f.append(Finding("header", f"Sender domain {from_dom} looks like a typo-squat of '{brand}'", 18))
            break

    if "xn--" in from_dom:
        f.append(Finding("header", "Sender domain uses punycode (possible homograph attack)", 12))

    # --- Structural anomalies --------------------------------------------
    if not msg.get("Message-ID"):
        f.append(Finding("header", "Missing Message-ID header", 5))
    if not msg.get("Date"):
        f.append(Finding("header", "Missing Date header", 3))
    if len(msg.get_all("Received", [])) > 8:
        f.append(Finding("header", "Unusually long Received chain (>8 hops)", 3))
    if str(msg.get("X-Priority", "")).strip().startswith("1"):
        f.append(Finding("header", "Email flagged high priority (common urgency tactic)", 2))
    return f
