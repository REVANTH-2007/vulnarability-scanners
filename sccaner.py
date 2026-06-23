import socket
import requests
import os
from datetime import datetime

TARGET = input("Enter IP address or domain: ")

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP"
}

open_ports = []
report = []

print(f"\nScanning {TARGET}...\n")

# Port Scan
for port in COMMON_PORTS:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((TARGET, port))

        if result == 0:
            service = COMMON_PORTS[port]
            open_ports.append((port, service))
            print(f"[OPEN] Port {port} ({service})")

            try:
                banner = ""
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode(errors="ignore")
                report.append(
                    f"Port {port} ({service}) - Banner: {banner[:100]}"
                )
            except:
                report.append(f"Port {port} ({service}) - Banner not available")

        sock.close()

    except:
        pass

# HTTP Header Check
try:
    response = requests.get(f"http://{TARGET}", timeout=5)

    server = response.headers.get("Server", "Unknown")

    report.append(f"\nServer Header: {server}")

    if server != "Unknown":
        report.append(
            "Potentially outdated server version detected. Verify manually."
        )

except:
    report.append("\nNo HTTP service detected.")

# Weak Configuration Checks
for port, service in open_ports:
    if port == 23:
        report.append(
            "WARNING: Telnet is enabled. Telnet transmits data in plaintext."
        )

    if port == 21:
        report.append(
            "WARNING: FTP detected. Consider using SFTP instead."
        )

# Create Report
os.makedirs("reports", exist_ok=True)

filename = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

with open(filename, "w") as f:
    f.write("=== Vulnerability Scan Report ===\n\n")
    f.write(f"Target: {TARGET}\n")
    f.write(f"Date: {datetime.now()}\n\n")

    for item in report:
        f.write(item + "\n")

print("\nScan Completed.")
print(f"Report saved to: {filename}")
