from flask import Flask, jsonify, request
import subprocess
import requests
import threading
import os
import time
import re
import psutil
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

# ── LOGGING SETUP ─────────────────────────────────────────────────────────────
LOG_PATH = r"D:\Downloads\GhostVPN\ghostvpn.log"

formatter = logging.Formatter(
    "[%(asctime)s] %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# FIXED (Step 2): Added explicit utf-8 encoding to prevent UnicodeDecodeError crashes
file_handler = RotatingFileHandler(LOG_PATH, maxBytes=2*1024*1024, backupCount=3, encoding='utf-8')
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.INFO)

logger = logging.getLogger("ghostvpn")
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# ── CONFIG ────────────────────────────────────────────────────────────────────
VPN_IP     = "51.20.8.80"

# Full-tunnel configs for each client
OVPN_CLIENTS = {
    "client1": r"D:\Downloads\VPNConfig\client1.ovpn",
    "client2": r"D:\Downloads\VPNConfig\client2.ovpn",
}
# Split-tunnel configs for each client
OVPN_SPLIT_CLIENTS = {
    "client1": r"D:\Downloads\VPNConfig\client1_split.ovpn",
    "client2": r"D:\Downloads\VPNConfig\client2_split.ovpn",
}

SERVER_KEY = r"D:\Downloads\GhostVPN\ghostvpn-key.pem"
HTML_PATH  = r"D:\Downloads\GhostVPN\indexvpn.html"

MAX_SESSION = 3600  # 1 hour

# ── STATE ─────────────────────────────────────────────────────────────────────
state = {
    "connected":     False,
    "timer_seconds": 0,
    "timer_running": False,
    "client_id":     "client1",
    "split_tunnel":  False,
}
_ovpn_proc       = None
_timer_thread    = None
_blocked_ips     = set()
_blocked_domains = set()
_last_bytes      = {"recv": 0, "sent": 0, "time": 0}

# ── HELPERS ───────────────────────────────────────────────────────────────────

def is_vpn_running():
    result = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq openvpn.exe"],
        capture_output=True, text=True
    )
    return "openvpn.exe" in result.stdout.lower()


def _fmt_time(s):
    h, rem = divmod(int(s), 3600)
    m, sec = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{sec:02d}"


def start_timer():
    global _timer_thread
    state["timer_seconds"] = 0
    state["timer_running"] = True

    def tick():
        while state["timer_running"]:
            time.sleep(1)
            state["timer_seconds"] += 1
            if MAX_SESSION > 0 and state["timer_seconds"] >= MAX_SESSION:
                logger.info("TIMER   | Session limit reached — auto-disconnecting")
                _do_disconnect()
                break

    _timer_thread = threading.Thread(target=tick, daemon=True)
    _timer_thread.start()


def stop_timer():
    state["timer_running"] = False
    state["timer_seconds"] = 0


def _do_connect(ovpn_path):
    global _ovpn_proc
    logger.info("CONNECT | Killing any existing openvpn.exe")
    subprocess.run(["taskkill", "/F", "/IM", "openvpn.exe"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    logger.info("CONNECT | Starting OpenVPN with config: %s", ovpn_path)
    _ovpn_proc = subprocess.Popen(
        [r"C:\Program Files\OpenVPN\bin\openvpn.exe", "--config", ovpn_path]
    )
    time.sleep(12)
    state["connected"] = True
    logger.info("CONNECT | Tunnel established. PID=%s", _ovpn_proc.pid)
    start_timer()


def _do_disconnect():
    global _ovpn_proc
    logger.info("DISCONNECT | Tearing down VPN tunnel")
    subprocess.run(["taskkill", "/F", "/IM", "openvpn.exe"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if _ovpn_proc:
        try:
            _ovpn_proc.terminate()
        except Exception:
            pass
        _ovpn_proc = None
    state["connected"] = False
    stop_timer()
    logger.info("DISCONNECT | Done")


def _get_bandwidth():
    global _last_bytes
    try:
        net = psutil.net_io_counters(pernic=True)
        tun = (
            net.get("Wi-Fi 3") or
            net.get("Ethernet") or
            net.get("OpenVPN Data Channel Offload") or
            net.get("OpenVPN TAP-Windows6") or
            psutil.net_io_counters()
        )
        now     = time.time()
        elapsed = (now - _last_bytes["time"]) if _last_bytes["time"] else 1
        dl      = max(0, (tun.bytes_recv - _last_bytes["recv"]) / elapsed)
        ul      = max(0, (tun.bytes_sent - _last_bytes["sent"]) / elapsed)
        _last_bytes = {"recv": tun.bytes_recv, "sent": tun.bytes_sent, "time": now}

        def fmt(bps):
            if bps >= 1024*1024: return f"{bps/1024/1024:.1f} MB/s"
            if bps >= 1024:      return f"{bps/1024:.1f} KB/s"
            return f"{bps:.0f} B/s"

        return fmt(dl), fmt(ul)
    except Exception:
        return "— KB", "— KB"


def _ssh(cmd):
    result = subprocess.run(
        ["ssh", "-i", SERVER_KEY,
         "-o", "StrictHostKeyChecking=no",
         "-o", "ConnectTimeout=10",
         f"ubuntu@{VPN_IP}", cmd],
        capture_output=True, text=True, timeout=20
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def _parse_blocked_output(output: str):
    ips     = set()
    domains = set()
    section = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.lower().startswith("blocked domains:"):
            section = "domains"; continue
        if line.lower().startswith("blocked ips:"):
            section = "ips"; continue
        if not line or line.lower() == "(none)":
            continue
        if section == "domains":
            parts = line.split()
            if parts:
                domain = parts[0].lower()
                if '.' in domain and re.search(r'[a-z]', domain):
                    domains.add(domain)
        elif section == "ips":
            found = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line)
            for ip in found:
                if ip != "0.0.0.0":
                    ips.add(ip)

    return ips, domains


def _sync_from_server():
    out, err, rc = _ssh("sudo python3 /home/ubuntu/show_blocked.py")
    if rc != 0:
        raise RuntimeError(f"show_blocked.py exited {rc}: {err}")
    ip_set, domain_set = _parse_blocked_output(out)
    return ip_set, domain_set, out


def _total_blocked_count():
    return len(_blocked_domains) + len(_blocked_ips)


# ── STARTUP SYNC ──────────────────────────────────────────────────────────────
def _startup_sync():
    global _blocked_ips, _blocked_domains
    try:
        ips, domains, _ = _sync_from_server()
        _blocked_ips     = ips
        _blocked_domains = domains
        logger.info("STARTUP | Synced: %d domains, %d IPs", len(_blocked_domains), len(_blocked_ips))
    except Exception as e:
        logger.warning("STARTUP | Could not sync blocked entries (non-fatal): %s", e)

threading.Thread(target=_startup_sync, daemon=True).start()


# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    try:
        return open(HTML_PATH, encoding="utf-8").read()
    except FileNotFoundError:
        return f"<h2>indexvpn.html not found at {HTML_PATH}</h2>", 404


@app.route("/connect", methods=["POST"])
def connect():
    if state["connected"] and is_vpn_running():
        return jsonify({"status": "already_connected"})

    data      = request.json or {}
    client_id = data.get("client_id", "client1")
    split     = data.get("split", False)

    state["client_id"]    = client_id
    state["split_tunnel"] = split

    # Pick the right .ovpn file
    if split:
        ovpn = OVPN_SPLIT_CLIENTS.get(client_id, OVPN_SPLIT_CLIENTS["client1"])
        if not os.path.exists(ovpn):
            ovpn = OVPN_CLIENTS.get(client_id, OVPN_CLIENTS["client1"])
            logger.warning("CONNECT | Split config not found, falling back to full tunnel")
    else:
        ovpn = OVPN_CLIENTS.get(client_id, OVPN_CLIENTS["client1"])

    logger.info("CONNECT | client_id=%s split=%s ovpn=%s", client_id, split, ovpn)

    try:
        _do_connect(ovpn)
        return jsonify({
            "status":    "connected",
            "client_id": client_id,
            "split":     split,
        })
    except Exception as e:
        state["connected"] = False
        logger.error("CONNECT | Failed: %s", e)
        return jsonify({"status": "error", "message": str(e)})


@app.route("/disconnect", methods=["POST"])
def disconnect():
    _do_disconnect()
    return jsonify({"status": "disconnected"})


@app.route("/status")
def status():
    running = is_vpn_running()
    if not running and state["connected"]:
        state["connected"] = False
        stop_timer()
        logger.warning("STATUS  | VPN process died unexpectedly")

    dl_str, ul_str = ("— KB", "— KB")
    if running:
        dl_str, ul_str = _get_bandwidth()

    t = state["timer_seconds"]
    return jsonify({
        "connected":     running,
        "timer":         _fmt_time(t),
        "timer_seconds": t,
        "remaining":     max(0, MAX_SESSION - t) if MAX_SESSION > 0 else 0,
        "max_session":   MAX_SESSION,
        "download":      dl_str,
        "upload":        ul_str,
        "blocked_count": _total_blocked_count(),
        "client_id":     state.get("client_id", "client1"),
        "split_tunnel":  state.get("split_tunnel", False),
    })


@app.route("/ip")
def get_ip():
    try:
        ip     = requests.get("https://api.ipify.org", timeout=6).text.strip()
        secure = (ip == VPN_IP)
        city = country = ""
        try:
            geo     = requests.get(f"http://ip-api.com/json/{ip}?fields=city,country", timeout=5).json()
            city    = geo.get("city", "")
            country = geo.get("country", "")
        except Exception:
            pass
        logger.info("IP      | current=%s secure=%s location=%s,%s", ip, secure, city, country)
        return jsonify({"ip": ip, "secure": secure, "vpn_ip": VPN_IP, "city": city, "country": country})
    except Exception as e:
        return jsonify({"ip": "Unable to fetch", "secure": False, "vpn_ip": VPN_IP,
                        "city": "", "country": "", "error": str(e)})


# FIXED (Step 3): Safe fallback routing strategy using auth-free endpoints
@app.route("/dns_leak")
def dns_leak():
    servers       = []
    leak_detected = False
    ip = country = isp = ""

    # All three are completely free with no auth token needed
    apis = [
        ("https://api.ipify.org?format=json", "ipify"),
        ("http://ip-api.com/json/?fields=query,country,countryCode,isp", "ipapi"),
        ("https://ipwho.is/", "ipwhois"),
    ]

    data, source = None, None
    for url, name in apis:
        try:
            r = requests.get(url, timeout=6)
            if r.status_code == 200:
                data   = r.json()
                source = name
                logger.info("DNS     | Using source: %s", name)
                break
        except Exception as e:
            logger.warning("DNS     | %s failed: %s", name, e)
            continue

    if data is None:
        return jsonify({
            "status":        "error",
            "message":       "All resolver APIs unavailable",
            "leak_detected": None,
            "servers":       [],
            "count":         0,
        })

    if source == "ipify":
        ip      = data.get("ip", "")
        # ipify only gives IP — do a second call to get geo
        try:
            geo     = requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode,isp", timeout=5).json()
            country = geo.get("countryCode", "")
            isp     = geo.get("isp", "")
        except Exception:
            country = ""
            isp     = ""
    elif source == "ipapi":
        ip      = data.get("query", "")
        country = data.get("countryCode", "")
        isp     = data.get("isp", "")
    elif source == "ipwhois":
        ip      = data.get("ip", "")
        country = data.get("country_code", "") or data.get("country", "")
        conn    = data.get("connection", {})
        isp     = conn.get("isp", "") if isinstance(conn, dict) else ""

    if ip:
        servers.append({"ip": ip, "country_name": country, "isp": isp})

    for srv in servers:
        c = srv.get("country_name", "").upper()
        i = srv.get("isp", "").lower()
        if c not in ("SE", "SWEDEN") and "amazon" not in i and "aws" not in i:
            leak_detected = True
            break

    logger.info("DNS     | leak=%s ip=%s country=%s source=%s",
                leak_detected, ip, country, source)

    return jsonify({
        "status":        "ok",
        "leak_detected": leak_detected,
        "servers":       servers,
        "count":         len(servers),
    })


@app.route("/ipv6_check")
def ipv6_check():
    """
    Tries to reach api6.ipify.org over IPv6.
    If it succeeds, IPv6 is exposed (leak). If it fails/times out, IPv6 is blocked (good).
    """
    try:
        res  = requests.get("https://api6.ipify.org", timeout=5)
        ipv6 = res.text.strip()
        logger.warning("IPv6    | EXPOSED: %s", ipv6)
        return jsonify({
            "ipv6_exposed": True,
            "ipv6":         ipv6,
            "message":      "IPv6 address is exposed — potential leak!",
        })
    except Exception:
        # Connection error means IPv6 is blocked — this is the good outcome
        logger.info("IPv6    | Blocked — no leak")
        return jsonify({
            "ipv6_exposed": False,
            "ipv6":         None,
            "message":      "IPv6 is blocked — no leak",
        })


@app.route("/ping_internal")
def ping_internal():
    """
    Tests reachability of the internal VPN resource at 10.8.0.1:8888.
    Only reachable when VPN tunnel is active.
    """
    INTERNAL_URL = "http://10.8.0.1:8888"
    try:
        res  = requests.get(INTERNAL_URL, timeout=5)
        data = res.json()
        logger.info("INTERNAL| Reachable — response: %s", data.get("message", "ok"))
        return jsonify({
            "status":      "ok",
            "reachable":   True,
            "internal_ip": "10.8.0.1",
            "response":    data,
        })
    except requests.exceptions.ConnectionError:
        logger.warning("INTERNAL| Unreachable — VPN may be down")
        return jsonify({
            "status":    "unreachable",
            "reachable": False,
            "message":   "Internal resource not reachable — VPN may be disconnected",
        })
    except Exception as e:
        logger.error("INTERNAL| Error: %s", e)
        return jsonify({"status": "error", "reachable": False, "message": str(e)})


@app.route("/logs")
def get_logs():
    """Returns last N lines of the structured log file for display in the UI."""
    try:
        n = int(request.args.get("lines", 60))
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return jsonify({
            "status": "ok",
            "lines":  lines[-n:],
            "total":  len(lines),
            "path":   LOG_PATH,
        })
    except FileNotFoundError:
        return jsonify({"status": "ok", "lines": ["Log file not created yet."], "total": 0})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/block", methods=["POST"])
def block():
    global _blocked_ips, _blocked_domains
    target = (request.json or {}).get("ip", "").strip()
    if not target:
        return jsonify({"status": "error", "message": "No target provided"})

    if re.search(r'[a-zA-Z]', target):
        server_script = f"sudo python3 /home/ubuntu/block_dns.py {target}"
    else:
        server_script = f"sudo python3 /home/ubuntu/block_ip.py {target}"

    ssh_msg = ""
    try:
        out, err, rc = _ssh(server_script)
        ssh_msg = out if rc == 0 else err
        if rc != 0:
            logger.error("BLOCK   | Server script error rc=%d: %s", rc, err)
    except Exception as e:
        ssh_msg = str(e)
        logger.error("BLOCK   | SSH error: %s", e)

    try:
        ips, domains, _ = _sync_from_server()
        _blocked_ips     = ips
        _blocked_domains = domains
        logger.info("BLOCK   | %s → domains=%d IPs=%d", target, len(_blocked_domains), len(_blocked_ips))
    except Exception as e:
        if re.search(r'[a-zA-Z]', target):
            _blocked_domains.add(target.lower().lstrip("www."))
        else:
            _blocked_ips.add(target)
        logger.warning("BLOCK   | Re-sync failed (%s), updated locally", e)

    return jsonify({
        "status":        "blocked",
        "ip":            target,
        "output":        ssh_msg,
        "blocked_count": _total_blocked_count(),
    })


@app.route("/unblock", methods=["POST"])
def unblock():
    global _blocked_ips, _blocked_domains
    target = (request.json or {}).get("ip", "").strip()
    if not target:
        return jsonify({"status": "error", "message": "No target provided"})

    if re.search(r'[a-zA-Z]', target):
        server_script = f"sudo python3 /home/ubuntu/unblock_dns.py {target}"
    else:
        server_script = f"sudo python3 /home/ubuntu/unblock_ip.py {target}"

    ssh_msg = ""
    try:
        out, err, rc = _ssh(server_script)
        ssh_msg = out if rc == 0 else err
        if rc != 0:
            logger.error("UNBLOCK | Server script error rc=%d: %s", rc, err)
    except Exception as e:
        ssh_msg = str(e)
        logger.error("UNBLOCK | SSH error: %s", e)

    try:
        ips, domains, _ = _sync_from_server()
        _blocked_ips     = ips
        _blocked_domains = domains
        logger.info("UNBLOCK | %s → domains=%d IPs=%d", target, len(_blocked_domains), len(_blocked_ips))
    except Exception as e:
        if re.search(r'[a-zA-Z]', target):
            _blocked_domains.discard(target.lower().lstrip("www."))
            _blocked_domains.discard(target.lower())
        else:
            _blocked_ips.discard(target)
        logger.warning("UNBLOCK | Re-sync failed (%s), updated locally", e)

    return jsonify({
        "status":        "unblocked",
        "ip":            target,
        "output":        ssh_msg,
        "blocked_count": _total_blocked_count(),
    })


@app.route("/show_blocked")
def show_blocked():
    global _blocked_ips, _blocked_domains
    try:
        ips, domains, raw_out = _sync_from_server()
        _blocked_ips     = ips
        _blocked_domains = domains
        return jsonify({
            "status":           "ok",
            "output":           raw_out if raw_out else "(none)",
            "blocked_count":    _total_blocked_count(),
            "blocked_ips":      sorted(list(_blocked_ips)),
            "blocked_domains": sorted(list(_blocked_domains)),
        })
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "SSH timeout", "blocked_count": _total_blocked_count()})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e), "blocked_count": _total_blocked_count()})


if __name__ == "__main__":
    import webbrowser
    threading.Timer(1.5, lambda: webbrowser.open("http://127.0.0.1:5001")).start()
    app.run(host="127.0.0.1", debug=False, port=5001, threaded=True)