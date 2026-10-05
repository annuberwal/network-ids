from scapy.all import IPv6, TCP, wrpcap


practice_packets = [
    IPv6(src="2001:db8::10", dst="2001:db8::20")
    / TCP(sport=43000 + number, dport=port, flags="S")
    for number, port in enumerate((22, 80, 443))
]

wrpcap("ipv6-sample.pcap", practice_packets)
print("Created ipv6-sample.pcap with 3 synthetic IPv6 TCP SYN packets.")
