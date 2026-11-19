# services/scanner/scan.py
# port scan for allowed targets

import socket

from services.scanner.targets import get_targets, is_allowed

# ports we check, with the service name for each one
PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    5432: "PostgreSQL",
    5433: "PostgreSQL (WatchTower)",
    8000: "WatchTower ingest API",
    8001: "WatchTower dashboard API",
    5173: "Vite dashboard",
    11434: "Ollama",
}


# knock on one port and report if it answers
def check_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0


# scan one target and collect its open ports
def scan_target(host):
    if not is_allowed(host):
        raise ValueError("target not allowed: " + host)
    open_ports = []
    for port, service in PORTS.items():
        if check_port(host, port):
            open_ports.append({"port": port, "service": service})
    return {"host": host, "open_ports": open_ports}


# scan every allowed target
def scan_all():
    results = []
    for target in get_targets():
        results.append(scan_target(target["host"]))
    return results


# print one result line per target
def main():
    for result in scan_all():
        print(result["host"], "open ports:", result["open_ports"])


if __name__ == "__main__":
    main()
