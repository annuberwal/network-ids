from ipaddress import ip_address
from collections import defaultdict, deque

from scapy.all import IP, IPv6, TCP, UDP


class IDSDetector:
    def __init__(self, settings):
        self.window = self._positive_number(settings, "window_seconds")
        self.port_threshold = self._positive_integer(
            settings, "port_scan_threshold"
        )
        self.syn_threshold = self._positive_integer(
            settings, "syn_attempt_threshold"
        )
        self.udp_threshold = self._positive_integer(
            settings, "udp_attempt_threshold"
        )
        self.packet_threshold = self._positive_integer(
            settings, "packet_rate_threshold"
        )
        self.ignored_source_ips = self._ignored_ip_addresses(settings)

        self.packet_times = defaultdict(deque)
        self.syn_times = defaultdict(deque)
        self.udp_times = defaultdict(deque)
        self.ports_by_pair = defaultdict(dict)
        self.alerted_scan_pairs = set()
        self.udp_ports_by_pair = defaultdict(dict)
        self.alerted_udp_scan_pairs = set()
        self.seen_unusual_flows = set()

    @staticmethod
    def _positive_number(settings, name):
        value = settings.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise ValueError(f"config.json setting '{name}' must be a positive number")
        return value

    @staticmethod
    def _positive_integer(settings, name):
        value = settings.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"config.json setting '{name}' must be a positive integer")
        return value

    @staticmethod
    def _ignored_ip_addresses(settings):
        addresses = settings.get("ignored_source_ips", [])
        if not isinstance(addresses, list) or any(
            not isinstance(address, str) for address in addresses
        ):
            raise ValueError(
                "config.json setting 'ignored_source_ips' must be a list of IP strings"
            )

        try:
            return {str(ip_address(address)) for address in addresses}
        except ValueError:
            raise ValueError(
                "config.json setting 'ignored_source_ips' contains an invalid IP address"
            ) from None

    def _remember_recent_time(self, time_queue, current_time):
        time_queue.append(current_time)

        while time_queue and current_time - time_queue[0] > self.window:
            time_queue.popleft()

        return len(time_queue)

    def _remember_recent_port(self, ports_by_pair, pair, port, current_time):
        recent_ports = ports_by_pair[pair]
        recent_ports[port] = current_time

        expired_ports = [
            seen_port
            for seen_port, seen_time in recent_ports.items()
            if current_time - seen_time > self.window
        ]
        for expired_port in expired_ports:
            del recent_ports[expired_port]

        return len(recent_ports)

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

        if source_ip in self.ignored_source_ips:
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

        if UDP in packet:
            udp = packet[UDP]

            recent_udp = self._remember_recent_time(
                self.udp_times[source_ip], packet_time
            )
            if recent_udp == self.udp_threshold:
                alerts.append((
                    "HIGH",
                    f"High UDP attempts: {source_ip} sent at least "
                    f"{self.udp_threshold} UDP packets within "
                    f"{self.window} seconds",
                ))

            pair = (source_ip, destination_ip)
            recent_udp_ports = self._remember_recent_port(
                self.udp_ports_by_pair, pair, udp.dport, packet_time
            )
            if recent_udp_ports < self.port_threshold:
                self.alerted_udp_scan_pairs.discard(pair)

            if (
                recent_udp_ports >= self.port_threshold
                and pair not in self.alerted_udp_scan_pairs
            ):
                self.alerted_udp_scan_pairs.add(pair)
                alerts.append((
                    "HIGH",
                    f"Possible UDP port scan: {source_ip} tried "
                    f"{self.port_threshold} ports against {destination_ip}",
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
            recent_tcp_ports = self._remember_recent_port(
                self.ports_by_pair, pair, tcp.dport, packet_time
            )
            if recent_tcp_ports < self.port_threshold:
                self.alerted_scan_pairs.discard(pair)
            if (
                recent_tcp_ports >= self.port_threshold
                and pair not in self.alerted_scan_pairs
            ):
                self.alerted_scan_pairs.add(pair)
                alerts.append((
                    "HIGH",
                    f"Possible port scan: {source_ip} tried "
                    f"{self.port_threshold} ports against {destination_ip}",
                ))

        return alerts
