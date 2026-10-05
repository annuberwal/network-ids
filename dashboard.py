import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
ALERTS_FILE = PROJECT_DIR / "alerts.txt"
DASHBOARD_FILE = PROJECT_DIR / "dashboard.html"
HOST = "127.0.0.1"
PORT = 8000


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = self.path.split("?", 1)[0]

        if route == "/api/alerts":
            self.send_alerts()
        elif route in ("/", "/index.html"):
            self.send_dashboard()
        else:
            self.send_error(404, "Not found")

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

        body = json.dumps({"alerts": alerts[-100:][::-1]}).encode("utf-8")
        self.send_response(200)
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
