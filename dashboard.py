import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from scapy.all import ICMP, IP, IPv6, TCP, UDP, rdpcap

from detector import IDSDetector


PROJECT_DIR = Path(__file__).resolve().parent
ALERTS_FILE = PROJECT_DIR / "alerts.txt"
DASHBOARD_FILE = PROJECT_DIR / "dashboard.html"
CONFIG_FILE = PROJECT_DIR / "config.json"
MAX_PCAP_BYTES = 20 * 1024 * 1024
HOST = "127.0.0.1"
PORT = 8000

with CONFIG_FILE.open(encoding="utf-8") as config_file:
    SETTINGS = json.load(config_file)


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = self.path.split("?", 1)[0]

        if route == "/api/alerts":
            self.send_alerts()
        elif route == "/api/captures":
            self.send_captures()
        elif route in ("/", "/index.html"):
            self.send_dashboard()
        else:
            self.send_error(404, "Not found")

    def do_POST(self):
        route = self.path.split("?", 1)[0]
        if route != "/api/analyze":
            self.send_error(404, "Not found")
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > 4096:
                self.send_json({"error": "Invalid request size."}, status=400)
                return
            request_data = json.loads(self.rfile.read(content_length))
            filename = request_data.get("filename")
            if not isinstance(filename, str) or Path(filename).name != filename:
                self.send_json({"error": "Choose a PCAP from the project folder."}, status=400)
                return

            capture_path = PROJECT_DIR / filename
            if (
                capture_path.suffix.lower() != ".pcap"
                or capture_path.resolve().parent != PROJECT_DIR.resolve()
                or not capture_path.is_file()
            ):
                self.send_json({"error": "Choose a PCAP from the project folder."}, status=400)
                return
            if capture_path.stat().st_size > MAX_PCAP_BYTES:
                self.send_json({"error": "PCAP is too large (maximum 20 MB)."}, status=413)
                return

            result = self.analyze_capture(capture_path)
            self.send_json(result)
        except (json.JSONDecodeError, UnicodeDecodeError, AttributeError, TypeError):
            self.send_json({"error": "Invalid analysis request."}, status=400)
        except Exception:
            self.send_json({"error": "Could not read that PCAP. Check that it is valid."}, status=400)

    def send_dashboard(self):
        page = DASHBOARD_FILE.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(page)

    def send_alerts(self):
        alerts = []
        if ALERTS_FILE.exists():
            for line in ALERTS_FILE.read_text(encoding="utf-8").splitlines():
                parts = line.split(" | ", 2)
                if len(parts) == 3:
                    timestamp, severity, message = parts
                    alerts.append({
                        "timestamp": timestamp,
                        "severity": severity,
                        "message": message,
                    })

        self.send_json({"alerts": alerts[-100:][::-1]})

    def send_captures(self):
        captures = []
        for path in sorted(PROJECT_DIR.glob("*.pcap")):
            if (
                path.is_file()
                and path.resolve().parent == PROJECT_DIR.resolve()
                and path.stat().st_size <= MAX_PCAP_BYTES
            ):
                captures.append(path.name)
        self.send_json({"captures": captures})

    def analyze_capture(self, capture_path):
        packets = rdpcap(str(capture_path))
        detector = IDSDetector(SETTINGS)
        protocols = {"TCP": 0, "UDP": 0, "ICMP": 0, "ICMPv6": 0, "Other": 0}
        source_counts = {}
        alerts = []
        ip_packet_count = 0

        for packet in packets:
            if IP in packet:
                source_ip = packet[IP].src
            elif IPv6 in packet:
                source_ip = packet[IPv6].src
            else:
                continue

            ip_packet_count += 1
            source_counts[source_ip] = source_counts.get(source_ip, 0) + 1

            if TCP in packet:
                protocols["TCP"] += 1
            elif UDP in packet:
                protocols["UDP"] += 1
            elif ICMP in packet:
                protocols["ICMP"] += 1
            elif any(layer.__name__.startswith("ICMPv6") for layer in packet.layers()):
                protocols["ICMPv6"] += 1
            else:
                protocols["Other"] += 1

            for severity, message in detector.inspect(packet):
                alerts.append({"severity": severity, "message": message})

        return {
            "filename": capture_path.name,
            "total_packets": len(packets),
            "ip_packets": ip_packet_count,
            "protocols": {name: count for name, count in protocols.items() if count},
            "sources": [
                {"ip": address, "count": count}
                for address, count in sorted(
                    source_counts.items(), key=lambda item: item[1], reverse=True
                )
            ],
            "alerts": alerts,
        }

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), DashboardHandler)
    print(f"IDS dashboard is running at http://{HOST}:{PORT}")
    print("Keep this terminal open. Press Ctrl+C to stop the dashboard.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()
