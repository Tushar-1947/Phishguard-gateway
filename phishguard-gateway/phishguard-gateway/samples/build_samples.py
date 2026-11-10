"""Builds the demo .eml files in this directory."""
import os
from email.message import EmailMessage

here = os.path.dirname(os.path.abspath(__file__))

def save(name, msg):
    with open(os.path.join(here, name), "wb") as fh:
        fh.write(msg.as_bytes())

# 1. Credential-harvesting phish
m = EmailMessage()
m["From"] = '"PayPal Security" <service@paypa1-secure-login.top>'
m["To"] = "victim@example.com"
m["Reply-To"] = "collect@mailbox-drop.xyz"
m["Return-Path"] = "<bounce@mailer-xyz.ru>"
m["Subject"] = "Urgent: your PayPal account has been suspended"
m["Date"] = "Mon, 09 Nov 2026 08:15:00 +0000"
m["Authentication-Results"] = "mx.example.com; spf=fail smtp.mailfrom=mailer-xyz.ru; dkim=none; dmarc=fail"
m.set_content("Dear customer, we detected suspicious activity. Your account will be suspended within 24 hours unless you verify your password. Click http://185.23.77.9/paypal/login/verify now.")
m.add_alternative('<html><body><p>Dear customer, we detected suspicious activity on your account. '
                  'Your account will be suspended unless you verify your identity.</p>'
                  '<a href="http://185.23.77.9/paypal/login/verify">https://www.paypal.com/signin</a></body></html>', subtype="html")
save("phishing_credential.eml", m)

# 2. Malware attachment
m = EmailMessage()
m["From"] = "Accounts <billing@invoices-dhl-express.click>"
m["To"] = "finance@example.com"
m["Subject"] = "Invoice overdue - immediate payment required"
m["Message-ID"] = "<abc123@invoices-dhl-express.click>"
m["Date"] = "Mon, 09 Nov 2026 09:00:00 +0000"
m["Authentication-Results"] = "mx.example.com; spf=softfail; dkim=none; dmarc=none"
m.set_content("Attached is the overdue invoice. Open the attachment and enable macros to view the document. Payment must be made immediately to avoid legal action.")
m.add_attachment(b"MZ\x90\x00fake-binary-for-testing", maintype="application", subtype="octet-stream", filename="Invoice_4471.pdf.exe")
m.add_attachment(b"PK\x03\x04fake", maintype="application", subtype="vnd.ms-excel.sheet.macroEnabled.12", filename="Statement.xlsm")
save("phishing_malware_attachment.eml", m)

# 3. CEO fraud / BEC (no links, text only)
m = EmailMessage()
m["From"] = '"Rahul Mehta (CEO)" <ceo.rahul.office@gmail.com>'
m["To"] = "accounts@example.com"
m["Reply-To"] = "rahul.private@outlook.com"
m["Subject"] = "Re: wire transfer needed today, keep confidential"
m["Message-ID"] = "<bec001@gmail.com>"
m["Date"] = "Mon, 09 Nov 2026 10:30:00 +0000"
m["Authentication-Results"] = "mx.example.com; spf=pass; dkim=pass; dmarc=pass"
m.set_content("I need you to process an urgent payment to a new vendor. I am in a meeting and cannot talk. Purchase gift cards and send me the codes. Do not tell anyone. Reply as soon as possible.")
save("bec_ceo_fraud.eml", m)

# 4. Legitimate mail
m = EmailMessage()
m["From"] = "Priya Sharma <priya@example.com>"
m["To"] = "team@example.com"
m["Subject"] = "Meeting notes from Tuesday"
m["Message-ID"] = "<notes-2201@example.com>"
m["Date"] = "Tue, 10 Nov 2026 11:00:00 +0000"
m["Authentication-Results"] = "mx.example.com; spf=pass; dkim=pass; dmarc=pass"
m.set_content("Hi team, here are the notes from our meeting. We agreed to finish the design review by Thursday and start implementation next week. Details: https://docs.example.com/notes/2201")
save("legitimate_meeting.eml", m)
print("samples built")
