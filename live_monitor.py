import argparse
import json
from datetime import datetime

from detector import IDSDetector
from scapy.all import sniff

with open("config.json", encoding="utf-8") as config_file:
    settings = json.load(config_file)

detector = IDSDetector(settings)


def inspect_packet(packet):
    for severity, message in detector.inspect(packet):
        timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
        line = f"{timestamp} | {severity} | {message}"
        print(line)

        with open("alerts.txt", "a") as alert_file:
            alert_file.write(line + "\n")


parser = argparse.ArgumentParser(description="Monitor authorized lab traffic.")
parser.add_argument("--interface", default="lo", help="Interface to monitor")
args = parser.parse_args()

print(f"Monitoring {args.interface}. Press Ctrl+C to stop.")

try:
    sniff(iface=args.interface, prn=inspect_packet, store=False)
except KeyboardInterrupt:
    print("\nMonitoring stopped.")
except PermissionError:
    print("Permission denied. Run this script with sudo for live capture.")
