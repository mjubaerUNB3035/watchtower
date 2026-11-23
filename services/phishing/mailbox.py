# mailbox.py

import email
import imaplib
import os
import re
from email.header import decode_header
from email.utils import parseaddr

from dotenv import load_dotenv

from services.phishing.checks import run_checks
from services.phishing.database import create_table, report_exists, save_report

load_dotenv()

IMAP_HOST = "imap.gmail.com"


# Connect mailbox
def connect():
    address = os.getenv("GMAIL_ADDRESS")
    password = os.getenv("GMAIL_APP_PASSWORD")
    box = imaplib.IMAP4_SSL(IMAP_HOST)
    box.login(address, password)
    box.select("INBOX")
    return box


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
    texts = []
    htmls = []
    if message.is_multipart():
        parts = message.walk()
    else:
        parts = [message]
    for part in parts:
        kind = part.get_content_type()
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        if kind == "text/plain":
            texts.append(payload.decode("utf-8", errors="replace"))
        if kind == "text/html":
            htmls.append(payload.decode("utf-8", errors="replace"))
    return texts, htmls


# Find links
def find_links(texts, htmls):
    links = []
    for html in htmls:
        found = re.findall(r'href=["\'](https?://[^"\']+)', html)
        for link in found:
            if link not in links:
                links.append(link)
    for text in texts:
        found = re.findall(r"https?://[^\s<>\"']+", text)
        for link in found:
            if link not in links:
                links.append(link)
    return links


# Attachment names
def attachment_names(message):
    names = []
    if message.is_multipart():
        for part in message.walk():
            name = part.get_filename()
            if name is not None:
                names.append(decode_text(name))
    return names


# Parse email
def parse_email(raw_bytes):
    message = email.message_from_bytes(raw_bytes)
    name, address = parseaddr(message.get("From", ""))
    texts, htmls = body_text(message)
    parsed = {
        "sender": address.lower(),
        "sender_name": decode_text(name),
        "subject": decode_text(message.get("Subject", "")),
        "links": find_links(texts, htmls),
        "attachments": attachment_names(message),
        "message_id": (message.get("Message-ID") or "").strip(),
    }
    return parsed


# Pull new emails
def pull_new(limit=10):
    create_table()
    box = connect()
    saved = 0
    try:
        status, data = box.uid("search", None, "ALL")
        uids = data[0].split()
        recent = uids[-limit:]
        for uid in recent:
            status, fetched = box.uid("fetch", uid, "(BODY.PEEK[])")
            raw = fetched[0][1]
            parsed = parse_email(raw)
            if parsed["message_id"] and report_exists(parsed["message_id"]):
                continue
            findings = run_checks(parsed)
            save_report(parsed, findings)
            saved += 1
    finally:
        box.logout()
    return saved


# Run monitor
def main():
    saved = pull_new()
    print("saved:", saved)


if __name__ == "__main__":
    main()