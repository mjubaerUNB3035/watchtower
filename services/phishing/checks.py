# checks.py

import ipaddress

# Lists
BRANDS = {
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "netflix": "netflix.com",
}

FREE_MAIL = ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com")

SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "ow.ly")

DANGEROUS_TYPES = (
    "exe", "scr", "js", "vbs", "bat", "cmd",
    "ps1", "msi", "iso", "img", "jar", "hta", "lnk",
)

MACRO_TYPES = ("docm", "xlsm", "pptm")

PRESSURE_WORDS = (
    "urgent", "verify", "immediately", "password", "closed",
    "suspended", "expire", "winner", "prize", "act now",
)


# Read Parts

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


# Unswap letters
def unswapped(text):
    swaps = {"0": "o", "1": "l", "3": "e", "5": "s", "@": "a"}
    letters = []
    for letter in text:
        if letter in swaps:
            letters.append(swaps[letter])
        else:
            letters.append(letter)
    return "".join(letters)


# Is IP
def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# Brand Checks

# Imitated brand
def imitated_brand(domain):
    plain = unswapped(registered_domain(domain))
    plain_full = unswapped(domain)
    for brand, real_domain in BRANDS.items():
        if brand in plain or brand in plain_full:
            if registered_domain(domain) != real_domain:
                return brand
    return None


# Sender

# Check sender
def check_sender(email):
    findings = []
    domain = domain_of(email["sender"])
    brand = imitated_brand(domain)
    if brand is not None:
        findings.append({
            "check": "sender",
            "detail": "sender domain imitates " + brand + ": " + domain,
        })
    if domain in FREE_MAIL:
        name = email.get("sender_name", "").lower()
        for brand in BRANDS:
            if brand in name:
                findings.append({
                    "check": "sender",
                    "detail": "free mail address claims to be " + brand,
                })
    return findings


# Links

# Check link
def check_link(link):
    findings = []
    host = host_of(link)
    if is_ip(host):
        findings.append({
            "check": "link",
            "detail": "link goes to an IP address, not a name: " + host,
        })
    if registered_domain(host) in SHORTENERS:
        findings.append({
            "check": "link",
            "detail": "link uses a shortener, real destination hidden: " + host,
        })
    if "@" in link.split("://")[-1].split("/")[0]:
        findings.append({
            "check": "link",
            "detail": "link hides its real host behind an @ sign",
        })
    brand = imitated_brand(host)
    if brand is not None:
        findings.append({
            "check": "link",
            "detail": "link host imitates " + brand + ": " + host,
        })
    return findings


# Check links
def check_links(email):
    findings = []
    for link in email["links"]:
        for finding in check_link(link):
            findings.append(finding)
    return findings


# Attachments

# Check attachment
def check_attachment(name):
    findings = []
    lower = name.lower()
    extension = lower.split(".")[-1]
    if extension in DANGEROUS_TYPES:
        findings.append({
            "check": "attachment",
            "detail": "dangerous attachment type ." + extension + ": " + name,
        })
    if extension in MACRO_TYPES:
        findings.append({
            "check": "attachment",
            "detail": "attachment can carry macros: " + name,
        })
    if lower.count(".") >= 2:
        findings.append({
            "check": "attachment",
            "detail": "double extension hides the real type: " + name,
        })
    return findings


# Check attachments
def check_attachments(email):
    findings = []
    for name in email["attachments"]:
        for finding in check_attachment(name):
            findings.append(finding)
    return findings


# Subject

# Check subject
def check_subject(email):
    findings = []
    subject = email["subject"].lower()
    matched = []
    for word in PRESSURE_WORDS:
        if word in subject:
            matched.append(word)
    if matched:
        findings.append({
            "check": "subject",
            "detail": "subject uses pressure words: " + ", ".join(matched),
        })
    return findings


# Run

# Run checks
def run_checks(email):
    findings = []
    for finding in check_sender(email):
        findings.append(finding)
    for finding in check_links(email):
        findings.append(finding)
    for finding in check_attachments(email):
        findings.append(finding)
    for finding in check_subject(email):
        findings.append(finding)
    return findings
