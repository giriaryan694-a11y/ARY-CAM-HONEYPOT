#!/usr/bin/env python3
import os
import re
import json
import secrets
import threading
from datetime import datetime
from collections import defaultdict

from colorama import Fore, Style, init as colorama_init
from termcolor import colored
import pyfiglet

from flask import Flask, Response, request, render_template, send_file, redirect, abort, session, url_for

colorama_init(autoreset=True)

# ---- Flask app ----
app = Flask(__name__, template_folder="templates")
app.secret_key = secrets.token_urlsafe(24)

# ---- filesystem layout ----
DETAIL_DIR = "detailed_logs"
LOG_FILE = "logs.txt"
MALICIOUS_FILE = "malicious.txt"
TEMPLATE_DIR = "templates"
STATIC_DIR = "static"

os.makedirs(DETAIL_DIR, exist_ok=True)
os.makedirs(TEMPLATE_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# ---- minimal templates if missing ----
if not os.path.exists(os.path.join(TEMPLATE_DIR, "login.html")):
    with open(os.path.join(TEMPLATE_DIR, "login.html"), "w") as f:
        f.write("""<!doctype html>
<html><head><meta charset="utf-8"><title>Login</title></head>
<body style="font-family:Arial,Helvetica,sans-serif;background:#0b1220;color:#e6eef6;padding:20px;">
  <h2>Camera Login</h2>
  <form method="POST">
    <input name="username" placeholder="username"><br><br>
    <input name="password" type="password" placeholder="password"><br><br>
    <button type="submit">Login</button>
  </form>
</body></html>""")

if not os.path.exists(os.path.join(TEMPLATE_DIR, "user_dashboard.html")):
    with open(os.path.join(TEMPLATE_DIR, "user_dashboard.html"), "w") as f:
        f.write("""<!doctype html>
<html><head><meta charset="utf-8"><title>Camera Panel</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:Arial,Helvetica,sans-serif;background:#0f1722;color:#e6eef6;margin:0;padding:20px}
.container{max-width:1100px;margin:0 auto}
.card{background:#0b1220;padding:16px;border-radius:8px}
.row{display:flex;gap:16px;flex-wrap:wrap}
.video{flex:1 1 640px;min-width:320px}
.controls{width:260px}
img{width:100%;border-radius:6px;display:block}
.btn{display:inline-block;padding:8px 12px;margin:6px 0;border-radius:6px;background:#2563eb;color:white;text-decoration:none}
label{display:block;margin-top:8px;font-size:13px;color:#cbd5e1}
small{color:#94a3b8}
</style></head>
<body>
<div class="container">
  <div class="card">
    <h1>Camera Control Panel</h1>
    <div class="row">
      <div class="video">
        <div style="background:#000;border-radius:6px;padding:6px;">
          <img src="/video_feed" alt="Live camera feed">
        </div>
        <div style="margin-top:8px;">
          <a class="btn" href="/snapshot.jpg" target="_blank">Take Snapshot</a>
          <a class="btn" href="/camera/1/live" target="_blank">View Camera 1</a>
        </div>
      </div>
      <div class="controls card" style="padding:12px;">
        <h3 style="margin:0 0 8px 0;">Camera Controls</h3>
        <label>Resolution</label>
        <select><option>1920x1080</option><option>1280x720</option><option>640x480</option></select>
        <label>Stream Quality</label>
        <select><option>High</option><option>Medium</option><option>Low</option></select>
        <label>Brightness</label><input type="range" min="0" max="100" value="50">
        <div style="margin-top:16px;"><small>Firmware: 1.0.0</small><br><small>Model: IP Camera</small></div>
      </div>
    </div>
  </div>
</div>
</body></html>""")

# ---- default runtime config (overwritten by setup) ----
cfg = {
    "http_port": 8080,
    "server_banner": "Werkzeug/2.0",
    "admin_user": "admin",
    "admin_pass": "admin123",
    "enable_rtsp": False,
    "rtsp_server_header": "Hikvision-RTSP/1.0",
    "rtsp_sdp": (
        "v=0\r\n"
        "o=- 137847 1 IN IP4 127.0.0.1\r\n"
        "s=MediaStream\r\n"
        "t=0 0\r\n"
        "m=video 0 RTP/AVP 96\r\n"
        "a=rtpmap:96 H264/90000\r\n"
    ),
    "scan_limit": 10,
    "scan_window": 5,
    "brute_limit": 5,
    "brute_window": 300,
    "dashboard_secret_path": None,
    "onvif_vendor": "GenericVendor",
    "onvif_model": "GenericModel",
    "geoip_db": None
}

# trackers & locks
failed_attempts = defaultdict(list)
scan_activity = defaultdict(list)
log_lock = threading.Lock()

# optional geoip2
GEOIP_AVAILABLE = False
geoip_reader = None
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except Exception:
    GEOIP_AVAILABLE = False

# util funcs
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def write_file_atomic(path, text):
    with log_lock:
        with open(path, "a") as f:
            f.write(text + "\n")

def log_all(ip, endpoint, info):
    write_file_atomic(LOG_FILE, f"[{now_str()}] IP={ip} ENDPOINT={endpoint} INFO={info}")

def log_malicious(ip, reason):
    write_file_atomic(MALICIOUS_FILE, f"[{now_str()}] IP={ip} MALICIOUS={reason}")

def capture_request(ip, endpoint):
    safe_ep = endpoint.replace("/", "-").strip("-")
    filename = f"{DETAIL_DIR}/{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_{ip}_{safe_ep}.json"
    data = {
        "timestamp": now_str(),
        "ip": ip,
        "endpoint": endpoint,
        "method": request.method,
        "headers": dict(request.headers),
        "args": request.args.to_dict(),
        "form": request.form.to_dict(),
        "cookies": request.cookies,
        "raw": request.data.decode(errors="ignore")
    }
    with open(filename, "w") as fh:
        json.dump(data, fh, indent=2)

PATTERNS = {
    "XSS": r"(<script>|onerror=|alert\()",
    "SQLi": r"(union.*select|or 1=1|sleep\()",
    "LFI": r"(\.\./\.\./|\.\./etc/passwd)",
    "RCE": r"(;wget|;curl|bash -i|nc -e)",
    "Log4Shell": r"(\$\{jndi:ldap)",
    "Webshell": r"(<\?php|eval\(|base64_decode)"
}

def check_payload_and_flag(ip, content):
    if not content:
        return False
    for label, pattern in PATTERNS.items():
        if re.search(pattern, content, re.IGNORECASE):
            log_malicious(ip, f"Payload detected: {label}")
            return True
    return False

def update_bruteforce(ip):
    now_ts = datetime.timestamp(datetime.now())
    window = cfg["brute_window"]
    failed_attempts[ip] = [t for t in failed_attempts[ip] if now_ts - t <= window]
    failed_attempts[ip].append(now_ts)
    if len(failed_attempts[ip]) >= cfg["brute_limit"]:
        log_malicious(ip, f"Bruteforce detected ({len(failed_attempts[ip])} failures)")

def update_scan(ip, endpoint=None):
    now_ts = datetime.timestamp(datetime.now())
    window = cfg["scan_window"]
    scan_activity[ip] = [t for t in scan_activity[ip] if now_ts - t <= window]
    scan_activity[ip].append(now_ts)
    if len(scan_activity[ip]) >= cfg["scan_limit"]:
        log_malicious(ip, f"Rapid scan detected ({len(scan_activity[ip])} hits in {window}s)")

# GeoIP
_geoip_cache = {}
def lookup_geo(ip):
    if not GEOIP_AVAILABLE or not cfg.get("geoip_db"):
        return None
    if ip in _geoip_cache:
        return _geoip_cache[ip]
    try:
        global geoip_reader
        if not geoip_reader:
            geoip_reader = geoip2.database.Reader(cfg["geoip_db"])
        rec = geoip_reader.city(ip)
        info = {
            "country": rec.country.name,
            "subdivision": rec.subdivisions.most_specific.name,
            "city": rec.city.name,
            "latitude": rec.location.latitude,
            "longitude": rec.location.longitude,
            "postal": rec.postal.code
        }
        _geoip_cache[ip] = info
        return info
    except Exception:
        return None

# MJPEG generator
def mjpeg_stream_generator(video_path):
    try:
        import cv2
    except Exception:
        while True:
            path = os.path.join(STATIC_DIR, "snapshot.jpg")
            if os.path.exists(path):
                with open(path, "rb") as f:
                    jpg = f.read()
            else:
                jpg = b""
            yield (b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + jpg + b"\r\n")
    else:
        cap = cv2.VideoCapture(video_path) if os.path.exists(video_path) else None
        if cap is None or not cap.isOpened():
            while True:
                path = os.path.join(STATIC_DIR, "snapshot.jpg")
                if os.path.exists(path):
                    with open(path, "rb") as f:
                        jpg = f.read()
                else:
                    jpg = b""
                yield (b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + jpg + b"\r\n")
        else:
            while True:
                ret, frame = cap.read()
                if not ret:
                    cap.set(1, 0)
                    continue
                _, jpg = cv2.imencode('.jpg', frame)
                yield (b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + jpg.tobytes() + b"\r\n")

# ---- Flask routes ----
@app.after_request
def set_server_headers(resp):
    resp.headers["Server"] = cfg.get("server_banner", "Werkzeug/2.0")
    resp.headers["X-Device"] = "IPCamera"
    return resp

@app.route("/")
def index():
    return redirect("/admin")

@app.route("/favicon.ico")
def favicon():
    return "", 204

@app.route("/video_feed")
def video_feed():
    ip = request.remote_addr
    capture_request(ip, "/video_feed")
    log_all(ip, "/video_feed", "stream_requested")
    update_scan(ip, "/video_feed")
    return Response(mjpeg_stream_generator(os.path.join(STATIC_DIR, "camera_feed.mp4")),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

# LOGIN: sets session and redirects to secret panel path (neutral UI)
@app.route("/admin", methods=["GET", "POST"])
def admin():
    ip = request.remote_addr
    capture_request(ip, "/admin")
    log_all(ip, "/admin", request.method)
    update_scan(ip, "/admin")

    if request.method == "POST":
        form = request.form.to_dict()
        capture_request(ip, "/admin_post")
        log_all(ip, "/admin_post", json.dumps(form))
        check_payload_and_flag(ip, json.dumps(form))

        u = form.get("username", "")
        p = form.get("password", "")
        if u == cfg["admin_user"] and p == cfg["admin_pass"]:
            # set session and redirect to neutral panel (secret path)
            session['logged_in'] = True
            session['user'] = u
            secret = cfg.get("dashboard_secret_path") or ""
            return redirect("/" + secret + "/panel")
        else:
            update_bruteforce(ip)
            log_all(ip, "/admin_failed", f"{u}:{p}")
            return "Invalid credentials", 401

    return render_template("login.html")

@app.route("/camera/<int:id>/live")
def camera_live(id):
    ip = request.remote_addr
    capture_request(ip, f"/camera/{id}/live")
    log_all(ip, f"/camera/{id}/live", "view")
    update_scan(ip, f"/camera/{id}/live")
    return Response(mjpeg_stream_generator(os.path.join(STATIC_DIR, "camera_feed.mp4")),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route("/snapshot.jpg")
def snapshot():
    ip = request.remote_addr
    capture_request(ip, "/snapshot.jpg")
    log_all(ip, "/snapshot.jpg", "snapshot_requested")
    update_scan(ip, "/snapshot.jpg")
    path = os.path.join(STATIC_DIR, "snapshot.jpg")
    if os.path.exists(path):
        return send_file(path)
    return "", 404

@app.route("/cgi-bin/admin.cgi")
@app.route("/shell")
@app.route("/api/v1/user/list")
def trap_endpoints():
    ip = request.remote_addr
    ep = request.path
    capture_request(ip, ep)
    log_all(ip, ep, "vuln_probe")
    log_malicious(ip, f"Tried vulnerable endpoint {ep}")
    update_scan(ip, ep)
    return "Internal Server Error", 500

@app.route("/etc/passwd")
def etc_passwd():
    ip = request.remote_addr
    log_malicious(ip, "Tried reading /etc/passwd")
    capture_request(ip, "/etc/passwd")
    return "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin", 200

@app.route("/config.php")
def config_php():
    ip = request.remote_addr
    log_malicious(ip, "Opened config.php")
    capture_request(ip, "/config.php")
    return "<?php $db_user='root'; $db_pass='changeme'; ?>", 200

# RTSP over HTTP-like
@app.route("/rtsp/<path:stream>", methods=["GET", "POST"])
def fake_rtsp(stream):
    ip = request.remote_addr
    capture_request(ip, f"/rtsp/{stream}")
    log_all(ip, f"/rtsp/{stream}", "rtsp_probe")
    update_scan(ip, f"/rtsp/{stream}")
    raw = request.data.decode(errors="ignore")
    check_payload_and_flag(ip, raw)
    raw_upper = raw.upper()
    if "OPTIONS" in raw_upper:
        return Response("RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY\r\n\r\n",
                        mimetype="text/plain")
    if "DESCRIBE" in raw_upper:
        sdp = cfg.get("rtsp_sdp", "")
        resp = ("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\n"
                f"Content-Length: {len(sdp)}\r\n\r\n{sdp}")
        return Response(resp, mimetype="text/plain")
    if "PLAY" in raw_upper:
        return Response(mjpeg_stream_generator(os.path.join(STATIC_DIR, "camera_feed.mp4")),
                        mimetype='multipart/x-mixed-replace; boundary=frame')
    return Response("RTSP/1.0 400 Bad Request\r\n\r\n", mimetype="text/plain")

# ONVIF
@app.route("/onvif/device_service", methods=["POST", "GET"])
def onvif_device_service():
    ip = request.remote_addr
    capture_request(ip, "/onvif/device_service")
    log_all(ip, "/onvif/device_service", "onvif_probe")
    update_scan(ip, "/onvif/device_service")
    vendor = cfg.get("onvif_vendor", "GenericVendor")
    model = cfg.get("onvif_model", "GenericModel")
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Envelope>
  <Body>
    <GetCapabilitiesResponse>
      <Device>
        <Manufacturer>{vendor}</Manufacturer>
        <Model>{model}</Model>
        <FirmwareVersion>1.0.0</FirmwareVersion>
        <HardwareId>0001</HardwareId>
        <SerialNumber>00000000</SerialNumber>
        <XAddr>http://{request.host}/onvif/device_service</XAddr>
        <Capabilities>
           <Analytics>true</Analytics>
           <Events>true</Events>
           <Media>true</Media>
           <PTZ>true</PTZ>
        </Capabilities>
      </Device>
    </GetCapabilitiesResponse>
  </Body>
</Envelope>"""
    return Response(xml, mimetype="application/xml")

# ----- SECRET ROUTES: panel (neutral) and logs (protected) -----
@app.route("/<path:maybe>/<path:subpath>")
def catch_secret_sub(maybe, subpath):
    # example: /<secret>/panel or /<secret>/logs
    secret = cfg.get("dashboard_secret_path") or ""
    if maybe != secret:
        return abort(404)
    # must be logged in to access secret subpaths
    if not session.get("logged_in"):
        return abort(404)
    if subpath == "panel":
        # neutral panel (no logs)
        return render_template("user_dashboard.html")
    if subpath == "logs":
        # protected logs view (secret)
        malicious = ""
        try:
            with open(MALICIOUS_FILE, "r") as f:
                malicious = f.read()
        except Exception:
            malicious = ""
        detailed_files = sorted(os.listdir(DETAIL_DIR))[-200:]
        # build a simple logs page
        html = "<html><body><h1>Secret Admin Logs</h1>"
        html += "<h2>Malicious Events</h2><pre>" + malicious + "</pre>"
        html += "<h2>Detailed Logs</h2><ul>"
        for fn in detailed_files:
            html += f'<li><a href="/_detailed/{fn}">{fn}</a></li>'
        html += "</ul></body></html>"
        return html
    return abort(404)

@app.route("/_detailed/<path:fname>")
def view_detailed(fname):
    # serve detailed log file (protected by session in secret logs link)
    safe_path = os.path.join(DETAIL_DIR, os.path.basename(fname))
    if not os.path.exists(safe_path):
        return abort(404)
    # optionally require session to view (we allow if session exists)
    if not session.get("logged_in"):
        return abort(404)
    try:
        with open(safe_path, "r") as fh:
            content = fh.read()
    except Exception:
        content = ""
    return "<pre>" + content + "</pre>"

# ---- Setup / Terminal UI ----
def print_banner():
    os.system("cls" if os.name == "nt" else "clear")
    art = pyfiglet.figlet_format("ARY CAM HONEYPOT", font="slant")
    print(colored(art, "cyan"))
    print(Fore.YELLOW + "               Made By Aryan Giri" + Style.RESET_ALL)
    print()

def prompt_setup():
    print_banner()
    print(Fore.CYAN + "[*] Configure ARY CAM HONEYPOT (press ENTER to accept defaults)\n" + Style.RESET_ALL)
    try:
        admin_user = input(Fore.YELLOW + f"Admin username [default: {cfg['admin_user']}]: " + Style.RESET_ALL).strip()
        if admin_user:
            cfg['admin_user'] = admin_user
        admin_pass = input(Fore.YELLOW + f"Admin password [default: {cfg['admin_pass']}]: " + Style.RESET_ALL).strip()
        if admin_pass:
            cfg['admin_pass'] = admin_pass
        port_in = input(Fore.YELLOW + f"HTTP port [default: {cfg['http_port']}]: " + Style.RESET_ALL).strip()
        if port_in:
            try:
                cfg['http_port'] = int(port_in)
            except:
                print(Fore.RED + "Invalid port; using default.")
        banner_in = input(Fore.YELLOW + f"HTTP Server banner header [default: {cfg['server_banner']}]: " + Style.RESET_ALL).strip()
        if banner_in:
            cfg['server_banner'] = banner_in
        # secret path
        secret_in = input(Fore.YELLOW + "Secret admin token path (e.g. mypanel) [press ENTER for random]: " + Style.RESET_ALL).strip()
        if secret_in:
            cfg['dashboard_secret_path'] = secret_in.strip().lstrip("/")
        else:
            cfg['dashboard_secret_path'] = secrets.token_urlsafe(8)
        # onvif vendor/model
        vendor_in = input(Fore.YELLOW + f"ONVIF vendor [default: {cfg['onvif_vendor']}]: " + Style.RESET_ALL).strip()
        if vendor_in:
            cfg['onvif_vendor'] = vendor_in
        model_in = input(Fore.YELLOW + f"ONVIF model [default: {cfg['onvif_model']}]: " + Style.RESET_ALL).strip()
        if model_in:
            cfg['onvif_model'] = model_in
        # RTSP
        rtsp_choice = input(Fore.YELLOW + "Enable RTSP simulation? (y/N): " + Style.RESET_ALL).strip().lower()
        if rtsp_choice == "y":
            cfg['enable_rtsp'] = True
            server_hdr = input(Fore.YELLOW + f"RTSP server header [default: {cfg['rtsp_server_header']}]: " + Style.RESET_ALL).strip()
            if server_hdr:
                cfg['rtsp_server_header'] = server_hdr
            print(Fore.BLUE + "Enter SDP body (press ENTER to use default):" + Style.RESET_ALL)
            sdp_in = input()
            if sdp_in.strip():
                cfg['rtsp_sdp'] = sdp_in
        # geoip
        geo_in = input(Fore.YELLOW + "GeoIP DB path (.mmdb) [press ENTER to skip]: " + Style.RESET_ALL).strip()
        if geo_in:
            if GEOIP_AVAILABLE and os.path.exists(geo_in):
                cfg['geoip_db'] = geo_in
                print(Fore.GREEN + "GeoIP configured." + Style.RESET_ALL)
            else:
                print(Fore.RED + "GeoIP not configured (missing geoip2 or file)." + Style.RESET_ALL)
        # detection tuning
        sl = input(Fore.YELLOW + f"Rapid-scan limit [default: {cfg['scan_limit']}]: " + Style.RESET_ALL).strip()
        if sl.isdigit():
            cfg['scan_limit'] = int(sl)
        sw = input(Fore.YELLOW + f"Scan window seconds [default: {cfg['scan_window']}]: " + Style.RESET_ALL).strip()
        if sw.isdigit():
            cfg['scan_window'] = int(sw)
        bl = input(Fore.YELLOW + f"Brute-force limit [default: {cfg['brute_limit']}]: " + Style.RESET_ALL).strip()
        if bl.isdigit():
            cfg['brute_limit'] = int(bl)
        bw = input(Fore.YELLOW + f"Brute window seconds [default: {cfg['brute_window']}]: " + Style.RESET_ALL).strip()
        if bw.isdigit():
            cfg['brute_window'] = int(bw)
        print()
        print(Fore.GREEN + "[+] Configuration complete." + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] HTTP port: {cfg['http_port']}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Secret panel will be at: /{cfg['dashboard_secret_path']}/panel" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Secret logs at: /{cfg['dashboard_secret_path']}/logs (session required)" + Style.RESET_ALL)
        if cfg.get('geoip_db'):
            print(Fore.GREEN + f"[+] GeoIP DB: {cfg['geoip_db']}" + Style.RESET_ALL)
        print()
    except KeyboardInterrupt:
        print("\nExiting.")
        exit(0)

def main():
    prompt_setup()
    host = "0.0.0.0"
    port = cfg['http_port']
    print(f"Starting on http://{host}:{port} (secret panel: /{cfg['dashboard_secret_path']}/panel)")
    try:
        app.run(host=host, port=port, debug=False)
    except Exception as e:
        print("Failed to start Flask app:", e)

if __name__ == "__main__":
    main()
