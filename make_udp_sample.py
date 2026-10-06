from scapy.all import IP, UDP, wrpcap

practice_packets = [
    IP(src="192.0.2.60", dst="192.0.2.70") / UDP(sport=43000, dport=53),
    IP(src="192.0.2.60", dst="192.0.2.70") / UDP(sport=43001, dport=123),
    IP(src="192.0.2.60", dst="192.0.2.70") / UDP(sport=43002, dport=161),
]

wrpcap("udp-scan-sample.pcap", practice_packets)
print("Created udp-scan-sample.pcap with 3 practice UDP packets.")
