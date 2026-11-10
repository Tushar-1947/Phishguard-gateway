"""Send a sample .eml through a running PhishGuard gateway.

Usage:  python scripts/send_test_mail.py samples/phishing_credential.eml [port]
"""
import smtplib
import sys

path = sys.argv[1]
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8025
data = open(path, "rb").read().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
try:
    with smtplib.SMTP("127.0.0.1", port, timeout=10) as s:
        s.sendmail("sender@test.local", ["victim@example.com"], data)
    print("ACCEPTED by gateway (clean or suspicious-tagged)")
except smtplib.SMTPDataError as e:
    print(f"REJECTED by gateway: {e.smtp_code} {e.smtp_error.decode()}")
