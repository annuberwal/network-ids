from collections import defaultdict, deque

from scapy.all import IP, IPv6, TCP


class IDSDetector:
    def __init__(self, settings):
        self.window = settings["window_seconds"]
        self.port_threshold = settings["port_scan_threshold"]
        self.syn_threshold = settings["syn_attempt_threshold"]
        self.packet_threshold = settings["packet_rate_threshold"]

        self.packet_times = defaultdict(deque)
        self.syn_times = defaultdict(deque)
        self.ports_by_pair = defaultdict(set)
        self.alerted_scan_pairs = set()
        self.seen_unusual_flows = set()

    def _remember_recent_time(self, time_queue, current_time):
        time_queue.append(current_time)

        while time_queue and current_time - time_queue[0] > self.window:
            time_queue.popleft()

        return len(time_queue)

    def inspect(self, packet):
        alerts = []

        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
        elif IPv6 in packet:
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst
        else:
            return alerts
        packet_time = float(packet.time)

        recent_packets = self._remember_recent_time(
            self.packet_times[source_ip], packet_time
        )
        if recent_packets == self.packet_threshold:
            alerts.append((
                "HIGH",
                f"High packet rate: {source_ip} sent at least "
                f"{self.packet_threshold} packets within {self.window} seconds",
            ))

        if TCP not in packet:
            return alerts

        tcp = packet[TCP]

        if int(tcp.flags) == 0:
            flow = (source_ip, destination_ip, tcp.sport, tcp.dport)
            if flow not in self.seen_unusual_flows:
                self.seen_unusual_flows.add(flow)
                alerts.append((
                    "MEDIUM",
                    f"TCP packet from {source_ip} has no flags",
                ))

        if int(tcp.flags) == 2:
            recent_syns = self._remember_recent_time(
                self.syn_times[source_ip], packet_time
            )
            if recent_syns == self.syn_threshold:
                alerts.append((
                    "HIGH",
                    f"High connection attempts: {source_ip} sent at least "
                    f"{self.syn_threshold} TCP SYN packets within "
                    f"{self.window} seconds",
                ))

            pair = (source_ip, destination_ip)
            self.ports_by_pair[pair].add(tcp.dport)
            if (
                len(self.ports_by_pair[pair]) >= self.port_threshold
                and pair not in self.alerted_scan_pairs
            ):
                self.alerted_scan_pairs.add(pair)
                alerts.append((
                    "HIGH",
                    f"Possible port scan: {source_ip} tried "
                    f"{self.port_threshold} ports against {destination_ip}",
                ))

        return alerts
