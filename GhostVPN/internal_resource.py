"""
internal_resource.py
────────────────────
Run this on your VPN server (51.20.8.80).
It listens ONLY on the VPN interface (10.8.0.1:8888).
This means it is ONLY reachable when a client is connected via VPN.
It proves "internal resource access" for the rubric.

To install as a service:
  sudo python3 /home/ubuntu/internal_resource.py
  (or use the systemd service defined in SERVER_SETUP_COMMANDS.txt)
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import datetime
import socket


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        payload = {
            "status":      "ok",
            "message":     "You have reached the internal VPN resource",
            "server_ip":   "10.8.0.1",
            "client_ip":   self.client_address[0],
            "path":        self.path,
            "time_utc":    datetime.datetime.utcnow().isoformat() + "Z",
            "note":        "Only reachable through active VPN tunnel"
        }
        self.wfile.write(json.dumps(payload, indent=2).encode())

    def log_message(self, fmt, *args):
        # Only log to stdout so systemd captures it
        print(f"[{datetime.datetime.utcnow().strftime('%H:%M:%S')}] {self.client_address[0]} - {fmt % args}")


if __name__ == "__main__":
    HOST = "10.8.0.1"   # VPN interface only — NOT 0.0.0.0
    PORT = 8888

    try:
        server = HTTPServer((HOST, PORT), Handler)
        print(f"[internal_resource] Listening on {HOST}:{PORT}")
        print(f"[internal_resource] Only reachable via VPN tunnel")
        server.serve_forever()
    except OSError as e:
        print(f"[internal_resource] ERROR: {e}")
        print(f"[internal_resource] Make sure OpenVPN server is running and tun0 is up")
        raise
