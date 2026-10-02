from scapy.all import IP, TCP,UDP, wrpcap

practice_packets = [
    IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=40000, dport=22, flags="S"),
    IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=40001, dport=80, flags="S"),
    IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=40002, dport=443, flags="S"),
]

wrpcap("scan-sample.pcap", practice_packets)
print("Created scan-sample.pcap with 3 practice TCP packets.")

normal_packets = [
    IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=41000, dport=443, flags="S"),
    IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=41001, dport=443, flags="S"),
]

normal_packets[0].time = 1000
normal_packets[1].time = 1020

wrpcap("normal-sample.pcap", normal_packets)
print("Created normal-sample.pcap with 2 spaced-out practice packets.")

unusual_packet = (
    IP(src="192.0.2.30", dst="192.0.2.40")
    / TCP(sport=42000, dport=443, flags=0)
)

wrpcap("unusual-sample.pcap", [unusual_packet])
print("Created unusual-sample.pcap with one TCP packet having no flags.")

burst_packets = [
    IP(src="192.0.2.50", dst="192.0.2.60")
    / UDP(sport=50000 + number, dport=9999)
    for number in range(25)
]

wrpcap("burst-sample.pcap", burst_packets)
print("Created burst-sample.pcap with 25 practice UDP packets.")
