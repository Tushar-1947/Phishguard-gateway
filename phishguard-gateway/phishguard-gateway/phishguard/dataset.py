"""Synthetic training-data generator.

The generated corpus is intended for *demonstration and testing*. For production-grade
accuracy retrain on real corpora (see README: Nazario phishing corpus, SpamAssassin,
Enron) using `python -m phishguard train --data your.csv`.
"""
import csv
import random

BRANDS = ["PayPal", "Microsoft", "Amazon", "Netflix", "Apple", "Google", "HDFC Bank", "SBI", "DHL", "LinkedIn"]

PHISH_SUBJECTS = [
    "Urgent: your {b} account has been suspended", "Action required: verify your {b} password",
    "{b} security alert - unusual sign-in detected", "Your {b} payment failed, update billing now",
    "Final notice: confirm your identity to avoid closure", "You have won a {b} gift card - claim now",
    "Invoice overdue - immediate payment required", "Package on hold: confirm delivery details",
    "Your mailbox storage is full, upgrade now", "Re: wire transfer needed today, keep confidential",
]
PHISH_BODIES = [
    "Dear customer, we detected suspicious activity on your {b} account. Your account will be suspended within 24 hours unless you verify your identity. Click here to login and confirm your password immediately.",
    "Your {b} subscription payment was declined. Update your credit card details and bank account information now to avoid service termination. Act immediately.",
    "Congratulations! You have been selected to receive a free {b} reward. To claim your prize provide your personal details and card number. Offer expires today.",
    "Security notice: someone tried to sign in to your {b} account from an unknown device. Confirm it was you by entering your username and password at the secure link below.",
    "I need you to process an urgent payment to a new vendor. I am in a meeting and cannot talk. Purchase gift cards and send me the codes. Do not tell anyone. Reply as soon as possible.",
    "Your parcel could not be delivered. A small customs fee is required. Pay now using the link to release your package, otherwise it will be returned to sender.",
    "Your account has been limited. Failure to update your information will result in permanent suspension. Verify your social security number and banking details to restore access.",
    "Attached is the overdue invoice. Open the attachment and enable macros to view the document. Payment must be made immediately to avoid legal action.",
]
HAM_SUBJECTS = [
    "Meeting notes from Tuesday", "Project timeline update", "Lunch on Friday?", "Weekly newsletter: product updates",
    "Re: code review for the billing module", "Your order has shipped", "Agenda for next week's planning session",
    "Quarterly report draft attached", "Thanks for your help yesterday", "Reminder: team offsite registration",
    "Receipt for your recent purchase", "Invitation: webinar on cloud security",
]
HAM_BODIES = [
    "Hi team, here are the notes from our meeting. We agreed to finish the design review by Thursday and start implementation next week. Let me know if I missed anything.",
    "Hello, just a reminder that the planning session is on Monday at 10 am in the main conference room. Please add your agenda items to the shared document beforehand.",
    "Thanks for sending over the draft. I made a few comments and suggestions in the document. Overall the structure looks good and the numbers match the finance summary.",
    "Hi, would you like to grab lunch on Friday? There is a new place near the office that serves great food. Let me know what time works for you.",
    "Your order #48213 has been shipped and should arrive within three to five business days. You can track the shipment from your account page on our website.",
    "Hi all, this week's newsletter covers the new release, upcoming features, and a few tips for getting the most out of the dashboard. Thanks for being a customer.",
    "I reviewed your pull request and left a few comments. The logic is solid, just rename the helper function and add a unit test for the edge case, then I will approve.",
    "Please find attached the quarterly report. The summary on page two highlights revenue growth and the main risks. I am happy to walk through it on a call.",
]
PHISH_NOISE = ["Thank you.", "Regards, Support Team", "Customer Service", "Do not reply to this message.", ""]
HAM_NOISE = ["Thanks.", "Best regards", "Cheers", "Please let me know if you have questions.", ""]


def generate(n_each: int = 600, seed: int = 42):
    rnd = random.Random(seed)
    rows = []
    for _ in range(n_each):
        b = rnd.choice(BRANDS)
        subj = rnd.choice(PHISH_SUBJECTS).format(b=b)
        body = " ".join([rnd.choice(PHISH_BODIES).format(b=b), rnd.choice(PHISH_NOISE)]).strip()
        if rnd.random() < 0.25:  # some phish are short / polite to reduce trivial separability
            body = "Hello, please review the document and verify your details here. " + rnd.choice(PHISH_NOISE)
        rows.append((f"{subj}\n{body}", 1))
    for _ in range(n_each):
        subj = rnd.choice(HAM_SUBJECTS)
        body = " ".join([rnd.choice(HAM_BODIES), rnd.choice(HAM_NOISE)]).strip()
        if rnd.random() < 0.15:  # legit mails that mention urgent/account words
            body += " This is urgent: please confirm your account access for the shared drive by end of day."
        rows.append((f"{subj}\n{body}", 0))
    rnd.shuffle(rows)
    return rows


def write_csv(path: str, n_each: int = 600, seed: int = 42):
    rows = generate(n_each, seed)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["text", "label"])
        w.writerows(rows)
    return len(rows)
