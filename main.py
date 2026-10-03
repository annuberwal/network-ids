import argparse
from collections import Counter
from collections import defaultdict
from datetime import datetime
import json 

with open("config.json", encoding="utf-8") as config_file:
    settings = json.load(config_file)

PORT_SCAN_THRESHOLD = settings["port_scan_threshold"]
SYN_ATTEMPT_THRESHOLD = settings["syn_attempt_threshold"]
PACKET_RATE_THRESHOLD = settings["packet_rate_threshold"]
ATTEMPT_WINDOW_SECONDS = settings["window_seconds"]

from scapy.all import IP, ICMP, TCP, UDP, rdpcap, sniff
from detector import IDSDetector

parser = argparse.ArgumentParser(description="Analyze a PCAP file for suspicious traffic.")
parser.add_argument("pcap", nargs="?", default="scan-sample.pcap")
parser.add_argument("--verbose", action="store_true", help="Show details for every packet")
parser.add_argument("--interface", help="Capture live traffic on this interface")
args = parser.parse_args()

if args.interface:
    print(f"Capturing on {args.interface}. Press Ctrl+C to stop.")
    packets = []

    try:
        sniff(
            iface=args.interface,
            count=5000,
            prn=packets.append,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nCapture stopped.")

    print(f"Captured {len(packets)} packets. Analyzing...")
else:
    packets = rdpcap(args.pcap)   
    
detector = IDSDetector(settings)      
    
packet_counts = Counter()
protocol_counts = Counter()

alert_count = 0
alerts = []

for number, packet in enumerate(packets, start=1):
    if IP not in packet:
        continue

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_counts[source_ip] += 1
    
    for severity, message in detector.inspect(packet):
        alert_count += 1
        alerts.append((severity, message))
        print(f"{severity}: {message}")
    
    if TCP in packet:
        description = (
            f"TCP {packet[TCP].sport} -> {packet[TCP].dport}"
        )
    elif UDP in packet:
        description = (
            f"UDP {packet[UDP].sport} -> {packet[UDP].dport}"
        )
    elif ICMP in packet:
        description = "ICMP"
    else:
        description = "Other IP traffic"
    
    protocol_counts[description.split()[0]] += 1    
           
    if args.verbose:
        print(
        f"Packet {number}: {source_ip} -> {destination_ip} | {description}"
    )
    
print("\nProtocol summary:")
for protocol, count in protocol_counts.items():
    print(f"{protocol}: {count}")    

print("\nDetection checks complete.")

print(f"\nAlerts found: {alert_count}")
print("-" * 30)

report_time = datetime.now().astimezone().isoformat(timespec="seconds")

with open("alerts.txt", "w") as alert_file:
    for severity, message in alerts:
        alert_file.write(
        f"{report_time} | {severity} | {message}\n"
        )

print("Alerts saved to alerts.txt")

print("\nPackets per source IP:")
for source_ip, count in packet_counts.items():
    print(f"{source_ip}: {count}")
    
