import argparse
import time
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import IP, TCP, sniff

with open("config.json", encoding="utf-8") as config_file:
    settings = json.load(config_file)

WINDOW_SECONDS = settings["window_seconds"]
PORT_SCAN_THRESHOLD = settings["port_scan_threshold"]
SYN_ATTEMPT_THRESHOLD = settings["syn_attempt_threshold"]
PACKET_RATE_THRESHOLD = settings["packet_rate_threshold"]

ports_by_pair = defaultdict(set)
syn_times_by_source = defaultdict(deque)
packet_times_by_source = defaultdict(deque)
seen_unusual_flows = set()


def add_recent_time(times, current_time):
    times.append(current_time)
    while times and current_time - times[0] > WINDOW_SECONDS:
        times.popleft()
    return len(times)


def alert(severity, message):
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    line = f"{timestamp} | {severity} | {message}"
    print(line)

    with open("alerts.txt", "a") as alert_file:
        alert_file.write(line + "\n")


def inspect_packet(packet):
    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    now = time.monotonic()

    packet_total = add_recent_time(packet_times_by_source[source_ip], now)
    if packet_total == PACKET_RATE_THRESHOLD:
        alert(
            "HIGH",
            f"High packet rate: {source_ip} sent at least "
            f"{PACKET_RATE_THRESHOLD} packets within {WINDOW_SECONDS} seconds",
        )

    if TCP not in packet:
        return

    tcp = packet[TCP]

    if int(tcp.flags) == 0:
        flow = (source_ip, destination_ip, tcp.sport, tcp.dport)
        if flow not in seen_unusual_flows:
            seen_unusual_flows.add(flow)
            alert("MEDIUM", f"TCP packet from {source_ip} has no flags")

    if int(tcp.flags) == 2:
        pair = (source_ip, destination_ip)
        ports_by_pair[pair].add(tcp.dport)

        syn_total = add_recent_time(syn_times_by_source[source_ip], now)
        if syn_total == SYN_ATTEMPT_THRESHOLD:
            alert(
                "HIGH",
                f"High connection attempts: {source_ip} sent at least "
                f"{SYN_ATTEMPT_THRESHOLD} TCP SYN packets within "
                f"{WINDOW_SECONDS} seconds",
            )

        if len(ports_by_pair[pair]) == PORT_SCAN_THRESHOLD:
            alert(
                "HIGH",
                f"Possible port scan: {source_ip} tried "
                f"{PORT_SCAN_THRESHOLD} ports against {destination_ip}",
            )


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
