import os
import smtplib
import socket
from email import message_from_bytes

from phishguard.gateway import run_gateway
from phishguard.ml_model import load_model

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def send(port, name):
    with open(os.path.join(SAMPLES, name), "rb") as fh:
        data = fh.read().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")  # SMTP needs CRLF
    with smtplib.SMTP("127.0.0.1", port, timeout=10) as s:
        return s.sendmail("a@b.com", ["victim@example.com"], data)


def test_gateway_rejects_and_quarantines_malicious(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    port = free_port()
    ctrl = run_gateway("127.0.0.1", port, model=load_model(), quarantine_dir=str(tmp_path / "q"))
    try:
        try:
            send(port, "phishing_credential.eml")
            raise AssertionError("malicious mail should have been rejected")
        except smtplib.SMTPDataError as e:
            assert e.smtp_code == 550
        assert len(list((tmp_path / "q").glob("*.eml"))) == 1
        assert len(list((tmp_path / "q").glob("*.json"))) == 1
    finally:
        ctrl.stop()


def test_gateway_accepts_clean_mail(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    port = free_port()
    ctrl = run_gateway("127.0.0.1", port, model=load_model(), quarantine_dir=str(tmp_path / "q"))
    try:
        assert send(port, "legitimate_meeting.eml") == {}
        assert not list((tmp_path / "q").glob("*.eml"))
    finally:
        ctrl.stop()


def test_gateway_relays_tagged_suspicious_mail(tmp_path, monkeypatch):
    """Chain: client -> PhishGuard -> downstream capture server."""
    from aiosmtpd.controller import Controller
    monkeypatch.chdir(tmp_path)
    captured = []

    class Sink:
        async def handle_DATA(self, server, session, envelope):
            captured.append(envelope.content); return "250 OK"

    sink_port, gw_port = free_port(), free_port()
    sink = Controller(Sink(), hostname="127.0.0.1", port=sink_port); sink.start()
    ctrl = run_gateway("127.0.0.1", gw_port, model=load_model(),
                       relay=f"127.0.0.1:{sink_port}", quarantine_dir=str(tmp_path / "q"))
    try:
        send(gw_port, "bec_ceo_fraud.eml")
        msg = message_from_bytes(captured[0])
        assert msg["X-PhishGuard-Verdict"] == "suspicious"
        assert msg["Subject"].startswith("[SUSPECTED PHISH]")
    finally:
        ctrl.stop(); sink.stop()
