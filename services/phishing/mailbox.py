# services/phishing/mailbox.py

import imaplib
import os
import re
from email import message_from_bytes
from email.header import decode_header
from email.utils import parseaddr
from pathlib import Path

from dotenv import load_dotenv

from services.phishing.checks import run_checks
from services.phishing.database import create_table, get_blocked_senders, report_exists, save_report

# load .env from project root
load_dotenv(Path(__file__).resolve().parents[2] / ".env")


# Connect
def connect():
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(os.getenv("GMAIL_ADDRESS"), os.getenv("GMAIL_APP_PASSWORD"))
    return mail


# Decode text
def decode_text(value):
    parts = decode_header(value or "")
    text = ""
    for data, charset in parts:
        if isinstance(data, bytes):
            text += data.decode(charset or "utf-8", errors="replace")
        else:
            text += data
    return text


# Body text
def body_text(message):
    text = ""
    html = ""
    for part in message.walk():
        content_type = part.get_content_type()
        if content_type == "text/plain":
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            text += payload.decode(charset, errors="replace")
        elif content_type == "text/html":
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            html += payload.decode(charset, errors="replace")
    return text, html


# Find links
def find_links(text, html):
    links = []
    for link in re.findall(r'href=["\'](https?://[^"\']+)', html or ""):
        if link not in links:
            links.append(link)
    for link in re.findall(r"https?://[^\s<>\"')]+", text or ""):
        link = link.rstrip(".,")
        if link not in links:
            links.append(link)
    return links


# Attachment names
def attachment_names(message):
    names = []
    for part in message.walk():
        name = part.get_filename()
        if name:
            names.append(decode_text(name))
    return names


# Auth results
def auth_results(message):
    headers = message.get_all("Authentication-Results") or []
    text = " ".join(headers).lower()
    results = {}
    for name in ("spf", "dkim", "dmarc"):
        match = re.search(name + r"=(\w+)", text)
        if match:
            results[name] = match.group(1)
    return results


# Parse email
def parse_email(raw):
    message = message_from_bytes(raw)
    sender_name, sender = parseaddr(message["From"] or "")
    sender_name = decode_text(sender_name)
    sender = sender.lower()
    reply_name, reply_to = parseaddr(message["Reply-To"] or "")
    reply_to = reply_to.lower()
    subject = decode_text(message["Subject"])
    text, html = body_text(message)
    links = find_links(text, html)
    attachments = attachment_names(message)
    return {
        "sender": sender,
        "sender_name": sender_name,
        "subject": subject,
        "links": links,
        "attachments": attachments,
        "message_id": message["Message-ID"],
        "reply_to": reply_to,
        "auth": auth_results(message),
    }


# Pull new
def pull_new(limit=10):
    create_table()
    # Get blocked senders
    blocked = get_blocked_senders()
    mail = connect()
    mail.select("INBOX")
    _, data = mail.search(None, "ALL")
    uids = data[0].split()
    saved = 0

    for uid in uids[-limit:]:
        _, msg = mail.fetch(uid, "(BODY.PEEK[])")
        email = parse_email(msg[0][1])

        if report_exists(email["message_id"]):
            continue

        findings = run_checks(email, blocked)
        save_report(email, findings)
        saved += 1

    mail.logout()
    return saved


# Main
def main():
    saved = pull_new()
    print(f"saved: {saved}")


if __name__ == "__main__":
    main()
