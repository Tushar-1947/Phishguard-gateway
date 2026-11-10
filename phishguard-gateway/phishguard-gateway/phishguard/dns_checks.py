"""Live DNS checks (SPF / DMARC policy lookup) and DKIM signature verification."""
from typing import List

from .models import Finding


def _txt(name: str):
    import dns.resolver
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=4)
        return ["".join(s.decode() for s in r.strings) for r in answers]
    except Exception:
        return []


def live_dns_checks(from_domain: str) -> List[Finding]:
    f: List[Finding] = []
    if not from_domain:
        return f
    spf = [t for t in _txt(from_domain) if t.lower().startswith("v=spf1")]
    if not spf:
        f.append(Finding("auth", f"{from_domain} publishes no SPF record", 6))
    elif " +all" in spf[0] or spf[0].rstrip().endswith("+all"):
        f.append(Finding("auth", f"{from_domain} SPF record allows any sender (+all)", 8))

    dmarc = [t for t in _txt("_dmarc." + from_domain) if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        f.append(Finding("auth", f"{from_domain} publishes no DMARC record", 6))
    elif "p=none" in dmarc[0].replace(" ", "").lower():
        f.append(Finding("auth", f"{from_domain} DMARC policy is p=none (monitor only)", 2))
    return f


def verify_dkim(raw: bytes) -> List[Finding]:
    """Cryptographically verify a DKIM-Signature (needs DNS access to fetch the key)."""
    import dkim
    f: List[Finding] = []
    if b"dkim-signature:" not in raw.lower():
        f.append(Finding("auth", "No DKIM-Signature header present", 4))
        return f
    try:
        ok = dkim.verify(raw)
    except Exception as exc:
        f.append(Finding("auth", f"DKIM verification error: {exc.__class__.__name__}", 5))
        return f
    if not ok:
        f.append(Finding("auth", "DKIM signature verification FAILED", 15))
    return f
