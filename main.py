import argparse
from collections import Counter
from collections import defaultdict

from scapy.all import IP, ICMP, TCP, UDP, rdpcap

PORT_SCAN_THRESHOLD = 3
SYN_ATTEMPT_THRESHOLD = 3
ATTEMPT_WINDOW_SECONDS = 10
syn_times_by_source = defaultdict(list)
parser = argparse.ArgumentParser(description="Analyze a PCAP file for suspicious traffic.")
parser.add_argument("pcap", nargs="?", default="scan-sample.pcap")
parser.add_argument("--verbose", action="store_true", help="Show details for every packet")
args = parser.parse_args()

packets = rdpcap(args.pcap)
packet_counts = Counter()
syn_attempts_by_source = Counter()
ports_by_pair = defaultdict(set)

alert_count = 0
alerts = []

for number, packet in enumerate(packets, start=1):
    if IP not in packet:
        continue

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_counts[source_ip] += 1
    
    
    if TCP in packet and int(packet[TCP].flags) == 0:
        alert_count += 1
        message = f"Unusual packet: TCP packet from {source_ip} has no flags"
        alerts.append(message)
        print(message)
    
    if TCP in packet and packet[TCP].flags == "S":
        syn_attempts_by_source[source_ip] += 1
        syn_times_by_source[source_ip].append(float(packet.time))
        ports_by_pair[(source_ip, destination_ip)].add(packet[TCP].dport)

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
        
           
    if args.verbose:
        print(
        f"Packet {number}: {source_ip} -> {destination_ip} | {description}"
    )

print("\nPort-scan check:")
for (source_ip, destination_ip), ports in ports_by_pair.items():
    if len(ports) >= PORT_SCAN_THRESHOLD:
        alert_count += 1
        alerts.append(
            f"Possible port scan: {source_ip} tried {len(ports)} ports against {destination_ip}"
        )
        print(
            f"Possible port scan: {source_ip} tried "
            f"{len(ports)} different ports against {destination_ip}"
        )
    else:
        print(
            f"{source_ip} -> {destination_ip}: "
            f"{len(ports)} different port(s), no alert"
        )
        
print("\nConnection-attempt check:")
for source_ip, times in syn_times_by_source.items():
    times = sorted(times)
    left = 0
    highest_in_window = 0

    for right in range(len(times)):
        while times[right] - times[left] > ATTEMPT_WINDOW_SECONDS:
            left += 1

        attempts_in_window = right - left + 1
        highest_in_window = max(highest_in_window, attempts_in_window)

    if highest_in_window >= SYN_ATTEMPT_THRESHOLD:
        alert_count += 1
        message = (
            f"High connection attempts: {source_ip} sent at least "
            f"{highest_in_window} TCP SYN packets within "
            f"{ATTEMPT_WINDOW_SECONDS} seconds"
        )
        alerts.append(message)
        print(message)
    else:
        print(
            f"{source_ip}: highest burst was {highest_in_window} SYN packets, "
            "no alert"
        )                   
        
print(f"\nAlerts found: {alert_count}")
print("-" * 30)

with open("alerts.txt", "w") as alert_file:
    for alert in alerts:
        alert_file.write(alert + "\n")

print("Alerts saved to alerts.txt")

print("\nPackets per source IP:")
for source_ip, count in packet_counts.items():
    print(f"{source_ip}: {count}")
    
