# services/phishing/checks.py

import ipaddress

# Lists
BRANDS = {
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "rbc": "rbc.com",
    "td": "td.com",
    "scotiabank": "scotiabank.com",
    "bmo": "bmo.com",
    "cra": "canada.ca",
    "canadapost": "canadapost.ca",
    "aircanada": "aircanada.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "chase": "chase.com",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
}

FREE_MAIL = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "yandex.com",
    "mail.com",
    "gmx.com",
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
}

DANGEROUS_TYPES = {
    "exe",
    "scr",
    "bat",
    "cmd",
    "com",
    "pif",
    "js",
    "jse",
    "vbs",
    "vbe",
    "wsf",
    "wsh",
    "jar",
    "msi",
    "ps1",
    "hta",
    "lnk",
    "html",
    "htm",
}

MACRO_TYPES = {"docm", "xlsm", "pptm"}

ARCHIVE_TYPES = {"zip", "rar", "7z"}

DOC_TYPES = {
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "txt",
    "jpg",
    "jpeg",
    "png",
}

PRESSURE_WORDS = [
    "urgent",
    "verify",
    "immediately",
    "password",
    "closed",
    "suspended",
    "locked",
    "expire",
    "confirm",
    "action required",
    "unauthorized",
    "alert",
    "warning",
    "limited",
    "restore",
]

MONEY_WORDS = [
    "gift card",
    "wire transfer",
    "bitcoin",
    "crypto",
    "e-transfer",
    "bank account",
    "western union",
    "moneygram",
    "cash app",
    "venmo",
    "zelle",
]

SWAPS = {"0": "o", "1": "l", "3": "e", "5": "s", "@": "a"}


# Address domain
def domain_of(address):
    parts = address.split("@")
    return parts[-1].strip().lower()


# Link host
def host_of(link):
    rest = link.split("://")[-1]
    authority = rest.split("/")[0]
    if "@" in authority:
        authority = authority.split("@")[-1]
    host = authority.split(":")[0]
    return host.lower()


# Registered domain
def registered_domain(host):
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    return labels[-2] + "." + labels[-1]


# Unswapped text
def unswapped(text):
    result = text.lower()
    for fake, real in SWAPS.items():
        result = result.replace(fake, real)
    return result


# Ip host
def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# Imitated brand
def imitated_brand(domain):
    own_domain = registered_domain(domain)
    clean_domain = unswapped(own_domain)
    clean_full = unswapped(domain)
    for brand, real_domain in BRANDS.items():
        if brand in clean_domain or brand in clean_full:
            if own_domain != real_domain:
                return brand
    return None


# Check sender
def check_sender(email):
    findings = []
    domain = domain_of(email["sender"])
    brand = imitated_brand(domain)
    if brand:
        findings.append(
            {
                "check": "fake sender",
                "detail": f"sender domain imitates {brand}: {domain}",
            }
        )
    name = (email.get("sender_name") or "").lower()
    if domain in FREE_MAIL:
        for brand in BRANDS:
            if brand in name:
                findings.append(
                    {
                        "check": "sender brand claim",
                        "detail": f"sender name claims {brand} but address is free mail: {domain}",
                    }
                )
                break
    return findings


# Check link
def check_link(link):
    findings = []
    host = host_of(link)
    if is_ip(host):
        findings.append(
            {
                "check": "dangerous link",
                "detail": f"link goes to an IP address, not a name: {host}",
            }
        )
        return findings
    authority = link.split("://")[-1].split("/")[0]
    if "@" in authority:
        findings.append(
            {
                "check": "trick link",
                "detail": f"link has @ before the host, real host is hidden: {host}",
            }
        )
    if host.startswith("xn--") or ".xn--" in host:
        findings.append(
            {
                "check": "fake link",
                "detail": f"link host uses punycode lookalike letters: {host}",
            }
        )
    brand = imitated_brand(host)
    if brand:
        findings.append(
            {
                "check": "fake link",
                "detail": f"link domain imitates {brand}: {registered_domain(host)}",
            }
        )
    if registered_domain(host) in SHORTENERS:
        findings.append(
            {
                "check": "hidden link",
                "detail": f"link uses a shortener, real destination hidden: {registered_domain(host)}",
            }
        )
    if link.lower().startswith("http://"):
        findings.append(
            {
                "check": "unsecure link",
                "detail": f"link is plain http, not https: {host}",
            }
        )
    labels = host.split(".")
    if len(labels) >= 4:
        findings.append(
            {
                "check": "deep subdomain link",
                "detail": f"link host stacks subdomains: {host}",
            }
        )
    return findings


# Check links
def check_links(email):
    findings = []
    for link in email.get("links") or []:
        findings.extend(check_link(link))
    return findings


# Check attachment
def check_attachment(name):
    findings = []
    parts = name.lower().split(".")
    last = parts[-1]
    if last in DANGEROUS_TYPES:
        findings.append(
            {
                "check": "dangerous attachment",
                "detail": f"dangerous attachment type .{last}: {name}",
            }
        )
    if len(parts) >= 3 and parts[-2] in DOC_TYPES:
        findings.append(
            {
                "check": "fake attachment",
                "detail": f"double extension hides the real type: {name}",
            }
        )
    if last in MACRO_TYPES:
        findings.append(
            {
                "check": "macro attachment",
                "detail": f"macro attachment type .{last} can run code: {name}",
            }
        )
    if last in ARCHIVE_TYPES:
        findings.append(
            {
                "check": "archive attachment",
                "detail": f"archive attachment .{last}, contents not seen: {name}",
            }
        )
    return findings


# Check attachments
def check_attachments(email):
    findings = []
    for name in email.get("attachments") or []:
        findings.extend(check_attachment(name))
    return findings


# Check subject
def check_subject(email):
    findings = []
    subject = (email.get("subject") or "").lower()
    found = []
    for word in PRESSURE_WORDS:
        if word in subject:
            found.append(word)
    if found:
        findings.append(
            {
                "check": "pressure subject",
                "detail": "subject uses pressure words: " + ", ".join(found),
            }
        )
    found_money = []
    for word in MONEY_WORDS:
        if word in subject:
            found_money.append(word)
    if found_money:
        findings.append(
            {
                "check": "money subject",
                "detail": "subject uses money words: " + ", ".join(found_money),
            }
        )
    return findings

# Check reply to
def check_reply_to(email):
    findings = []
    reply_to = email.get("reply_to") or ""
    if reply_to:
        sender_domain = domain_of(email["sender"])
        reply_domain = domain_of(reply_to)
        if reply_domain != sender_domain:
            findings.append(
                {
                    "check": "reply-to mismatch",
                    "detail": f"reply goes to {reply_domain}, sender is {sender_domain}",
                }
            )
    return findings


# Check auth
def check_auth(email):
    findings = []
    auth = email.get("auth") or {}
    failed = []
    for name in ("spf", "dkim", "dmarc"):
        if auth.get(name) == "fail":
            failed.append(name)
    if failed:
        findings.append(
            {
                "check": "failed authentication",
                "detail": "authentication failed: " + ", ".join(failed),
            }
        )
    return findings


# Check blocked sender Domain
def check_blocked(email, blocked):
    findings = []
    sender = email["sender"].lower()
    if sender in blocked:
        findings.append({
            "check": "blocked sender",
            "detail": "sender is on the blocked list: " + sender,
        })
    # extract the Domain 
    elif domain_of(email["sender"]) in blocked:
        findings.append({
            "check": "blocked sender",
            "detail": "sender domain is on the blocked list: "
                      + domain_of(email["sender"]),
        })
    return findings

# Run checks - passes to mailbox pull_new
def run_checks(email, blocked):
    findings = []
    findings = findings + check_blocked(email, blocked)
    findings += check_sender(email)
    findings += check_links(email)
    findings += check_attachments(email)
    findings += check_subject(email)
    findings += check_reply_to(email)
    findings += check_auth(email)
    return findings
