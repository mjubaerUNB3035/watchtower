# services/scanner/targets.py
# target device to Scan

# own machines only: this laptop and the linux vm
TARGETS = [
    {"name": "this laptop", "host": "127.0.0.1"},
    {"name": "watchtower-linux", "host": "192.168.56.101"},
]


# return the full list of allowed targets
def get_targets():
    return TARGETS


# check one host is on the allowed list
def is_allowed(host):
    for target in TARGETS:
        if target["host"] == host:
            return True
    return False