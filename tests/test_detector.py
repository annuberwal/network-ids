import unittest

from scapy.all import IP, IPv6, TCP, UDP

from detector import IDSDetector


SETTINGS = {
    "window_seconds": 10,
    "port_scan_threshold": 3,
    "syn_attempt_threshold": 3,
    "udp_attempt_threshold": 3,
    "packet_rate_threshold": 20,
    "ignored_source_ips": [],
}


def make_packet(layer, source, destination, transport, timestamp):
    packet = layer(src=source, dst=destination) / transport
    packet.time = timestamp
    return packet


class IDSDetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = IDSDetector(SETTINGS.copy())

    def tcp_syn(self, port, timestamp, source="192.0.2.10", destination="192.0.2.20"):
        return make_packet(
            IP,
            source,
            destination,
            TCP(sport=40000 + port, dport=port, flags="S"),
            timestamp,
        )

    def udp_packet(self, port, timestamp, source="192.0.2.10", destination="192.0.2.20"):
        return make_packet(
            IP,
            source,
            destination,
            UDP(sport=43000, dport=port),
            timestamp,
        )

    def test_tcp_port_scan_alerts_once_per_scan_window(self):
        results = [
            self.detector.inspect(self.tcp_syn(port, timestamp))
            for port, timestamp in ((22, 0), (80, 1), (443, 2), (8080, 3))
        ]

        scan_alerts = [
            message
            for packet_alerts in results
            for _severity, message in packet_alerts
            if "Possible port scan" in message
        ]
        self.assertEqual(len(scan_alerts), 1)

    def test_tcp_ports_outside_window_do_not_form_a_scan(self):
        results = [
            self.detector.inspect(self.tcp_syn(port, timestamp))
            for port, timestamp in ((22, 0), (80, 1), (443, 12))
        ]

        self.assertFalse(any(
            "Possible port scan" in message
            for packet_alerts in results
            for _severity, message in packet_alerts
        ))

    def test_tcp_syn_burst_alerts_within_window(self):
        results = [
            self.detector.inspect(self.tcp_syn(22, timestamp))
            for timestamp in (0, 1, 2)
        ]

        self.assertTrue(any(
            "High connection attempts" in message
            for _severity, message in results[-1]
        ))

    def test_tcp_syn_packets_outside_window_do_not_alert(self):
        results = [
            self.detector.inspect(self.tcp_syn(22, timestamp))
            for timestamp in (0, 1, 12)
        ]

        self.assertFalse(any(
            "High connection attempts" in message
            for packet_alerts in results
            for _severity, message in packet_alerts
        ))

    def test_new_tcp_scan_alerts_after_previous_window_expires(self):
        results = [
            self.detector.inspect(self.tcp_syn(port, timestamp))
            for port, timestamp in (
                (22, 0), (80, 1), (443, 2),
                (22, 20), (80, 21), (443, 22),
            )
        ]

        scan_alerts = [
            message
            for packet_alerts in results
            for _severity, message in packet_alerts
            if "Possible port scan" in message
        ]
        self.assertEqual(len(scan_alerts), 2)

    def test_udp_burst_and_scan_alerts(self):
        results = [
            self.detector.inspect(self.udp_packet(port, timestamp))
            for port, timestamp in ((53, 0), (123, 1), (161, 2))
        ]
        final_messages = [message for _severity, message in results[-1]]

        self.assertTrue(any("High UDP attempts" in message for message in final_messages))
        self.assertTrue(any("Possible UDP port scan" in message for message in final_messages))

    def test_udp_ports_outside_window_do_not_form_a_scan(self):
        results = [
            self.detector.inspect(self.udp_packet(port, timestamp))
            for port, timestamp in ((53, 0), (123, 1), (161, 12))
        ]

        self.assertFalse(any(
            "Possible UDP port scan" in message
            for packet_alerts in results
            for _severity, message in packet_alerts
        ))

    def test_udp_scan_can_alert_again_after_window_expires(self):
        results = [
            self.detector.inspect(self.udp_packet(port, timestamp))
            for port, timestamp in (
                (53, 0), (123, 1), (161, 2),
                (53, 20), (123, 21), (161, 22),
            )
        ]

        scan_alerts = [
            message
            for packet_alerts in results
            for _severity, message in packet_alerts
            if "Possible UDP port scan" in message
        ]
        self.assertEqual(len(scan_alerts), 2)

    def test_high_packet_rate_alerts_at_configured_threshold(self):
        results = [
            self.detector.inspect(self.udp_packet(53, timestamp))
            for timestamp in (index / 2 for index in range(20))
        ]

        self.assertTrue(any(
            "High packet rate" in message
            for _severity, message in results[-1]
        ))

    def test_tcp_packet_without_flags_is_marked_medium(self):
        packet = make_packet(
            IP,
            "192.0.2.30",
            "192.0.2.40",
            TCP(sport=45000, dport=443, flags=0),
            0,
        )

        alerts = self.detector.inspect(packet)

        self.assertIn(
            ("MEDIUM", "TCP packet from 192.0.2.30 has no flags"),
            alerts,
        )

    def test_ignored_source_ip_produces_no_alerts(self):
        settings = SETTINGS | {"ignored_source_ips": ["192.0.2.10"]}
        detector = IDSDetector(settings)

        alerts = [
            detector.inspect(self.tcp_syn(port, timestamp))
            for port, timestamp in ((22, 0), (80, 1), (443, 2))
        ]

        self.assertEqual(alerts, [[], [], []])

    def test_ipv6_tcp_scan_is_detected(self):
        detector = IDSDetector(SETTINGS.copy())
        packets = [
            make_packet(
                IPv6,
                "2001:db8::10",
                "2001:db8::20",
                TCP(sport=44000 + port, dport=port, flags="S"),
                timestamp,
            )
            for port, timestamp in ((22, 0), (80, 1), (443, 2))
        ]

        alerts = [
            message
            for packet in packets
            for _severity, message in detector.inspect(packet)
        ]

        self.assertTrue(any("Possible port scan" in message for message in alerts))

    def test_non_positive_threshold_is_rejected(self):
        settings = SETTINGS | {"port_scan_threshold": 0}

        with self.assertRaisesRegex(ValueError, "positive integer"):
            IDSDetector(settings)

    def test_invalid_ignored_ip_is_rejected(self):
        settings = SETTINGS | {"ignored_source_ips": ["not-an-ip"]}

        with self.assertRaisesRegex(ValueError, "invalid IP address"):
            IDSDetector(settings)


if __name__ == "__main__":
    unittest.main()
