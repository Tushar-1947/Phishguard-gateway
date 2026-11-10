"""SMTP gateway: receives mail, analyses it, then rejects / quarantines / tags / relays."""
import json
import logging
import os
import smtplib
import time
import uuid
from email import policy
from email.parser import BytesParser
from typing import Optional

from aiosmtpd.controller import Controller

from .analyzer import analyze, format_report

log = logging.getLogger("phishguard")


class PhishGuardHandler:
    def __init__(self, model=None, quarantine_dir="quarantine", relay: Optional[str] = None,
                 live_dns=False, vt_key="", reject_malicious=True):
        self.model, self.relay = model, relay
        self.qdir, self.live_dns, self.vt_key = quarantine_dir, live_dns, vt_key
        self.reject_malicious = reject_malicious
        os.makedirs(self.qdir, exist_ok=True)
        os.makedirs("logs", exist_ok=True)

    def _store(self, raw: bytes, report) -> str:
        qid = f"{int(time.time())}-{uuid.uuid4().hex[:8]}"
        with open(os.path.join(self.qdir, qid + ".eml"), "wb") as fh:
            fh.write(raw)
        with open(os.path.join(self.qdir, qid + ".json"), "w") as fh:
            json.dump(report.to_dict(), fh, indent=2)
        return qid

    def _tag(self, raw: bytes, report) -> bytes:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        for h in ("X-PhishGuard-Score", "X-PhishGuard-Verdict"):
            if h in msg:
                del msg[h]
        msg["X-PhishGuard-Score"] = str(report.score)
        msg["X-PhishGuard-Verdict"] = report.verdict
        if report.verdict == "suspicious" and not str(msg["Subject"]).startswith("[SUSPECTED PHISH]"):
            subj = str(msg["Subject"] or "")
            del msg["Subject"]
            msg["Subject"] = "[SUSPECTED PHISH] " + subj
        return msg.as_bytes()

    def _relay(self, envelope, data: bytes):
        host, _, port = self.relay.partition(":")
        with smtplib.SMTP(host, int(port or 25), timeout=15) as s:
            s.sendmail(envelope.mail_from, envelope.rcpt_tos, data)

    async def handle_DATA(self, server, session, envelope):
        raw = envelope.original_content or envelope.content
        report = analyze(raw, model=self.model, live_dns=self.live_dns, vt_key=self.vt_key)
        log.info("from=%s verdict=%s score=%s", envelope.mail_from, report.verdict, report.score)
        with open(os.path.join("logs", "gateway.jsonl"), "a") as fh:
            fh.write(json.dumps({"ts": time.time(), "mail_from": envelope.mail_from,
                                 "rcpt": envelope.rcpt_tos, "score": report.score,
                                 "verdict": report.verdict}) + "\n")
        if report.verdict == "malicious":
            qid = self._store(raw, report)
            log.warning("QUARANTINED %s\n%s", qid, format_report(report))
            return "550 5.7.1 Message rejected: classified as phishing" if self.reject_malicious else "250 OK (quarantined)"
        data = self._tag(raw, report)
        if report.verdict == "suspicious":
            self._store(data, report)
        if self.relay:
            try:
                self._relay(envelope, data)
            except Exception as exc:
                log.error("relay failed: %s", exc)
                return "451 4.4.0 Temporary relay failure"
        return "250 OK"


def run_gateway(host="127.0.0.1", port=8025, **kwargs):
    ctrl = Controller(PhishGuardHandler(**kwargs), hostname=host, port=port)
    ctrl.start()
    log.info("PhishGuard listening on %s:%s", host, port)
    return ctrl
