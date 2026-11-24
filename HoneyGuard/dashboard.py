"""
HoneyGuard Live Web Dashboard & Orchestrator — v2.0
Flask + Flask-SocketIO application providing real-time attack visualization,
intrusion alerts, 1-click Attack Simulator, HTTP Decoy Traps, and incident
response controls.

Cloud-aware: binds to 0.0.0.0:$PORT on Render/Railway, 127.0.0.1:5000 locally.
SSH honeypot and firewall commands are wrapped in try/except so restricted
cloud containers never crash.
"""

import os
import time
import socket
import threading
import subprocess
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, send_file, flash
)
from flask_socketio import SocketIO
import config
import db
import blocker
import canary
import report
from honeypot import HoneypotServer

# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = config.DASHBOARD_SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# ---------------------------------------------------------------------------
# Auth decorator
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------------------------
# WebSocket broadcast helpers
# ---------------------------------------------------------------------------
def on_honeypot_event(data: dict):
    """Broadcasts honeypot events to connected WebSockets."""
    with app.app_context():
        summary = db.get_analytics_summary()
        socketio.emit("new_attack", {"attack": data, "summary": summary})


def on_canary_event(data: dict):
    """Broadcasts canary trap breaches to connected WebSockets."""
    with app.app_context():
        summary = db.get_analytics_summary()
        socketio.emit("new_canary", {"canary": data, "summary": summary})


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if username == config.DASHBOARD_USERNAME and password == config.DASHBOARD_PASSWORD:
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("index"))
        flash("Invalid administrator credentials. Please check .env configuration.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Main dashboard
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    summary = db.get_analytics_summary()
    recent_attacks = db.get_recent_attacks(limit=25)
    recent_alerts = db.get_recent_alerts(limit=15)
    blocked_ips = db.get_blocked_ips()
    return render_template(
        "index.html",
        summary=summary,
        attacks=recent_attacks,
        alerts=recent_alerts,
        blocked_ips=blocked_ips,
        dry_run=config.DRY_RUN,
        honeypot_port=config.HONEYPOT_PORT
    )


# ---------------------------------------------------------------------------
# REST APIs
# ---------------------------------------------------------------------------
@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(db.get_analytics_summary())


@app.route("/api/attacks")
@login_required
def api_attacks():
    limit = request.args.get("limit", 50, type=int)
    return jsonify(db.get_recent_attacks(limit=limit))


@app.route("/api/alerts")
@login_required
def api_alerts():
    limit = request.args.get("limit", 25, type=int)
    return jsonify(db.get_recent_alerts(limit=limit))


@app.route("/api/blocked")
@login_required
def api_blocked():
    return jsonify(db.get_blocked_ips())


@app.route("/api/unblock/<ip>", methods=["POST"])
@login_required
def api_unblock(ip: str):
    res = blocker.unblock_ip(ip)
    return jsonify(res)


@app.route("/api/generate_report", methods=["POST"])
@login_required
def api_generate_report():
    try:
        pdf_path = report.generate_pdf_report()
        filename = Path(pdf_path).name
        return jsonify({"success": True, "filename": filename,
                        "download_url": f"/download_report/{filename}"})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route("/download_report/<filename>")
@login_required
def download_report(filename: str):
    safe_path = config.REPORTS_DIR / Path(filename).name
    if safe_path.exists():
        return send_file(safe_path, as_attachment=True)
    return "Report not found", 404


# ---------------------------------------------------------------------------
# 1-Click Attack Simulator  (POST /api/simulate/<type>)
# ---------------------------------------------------------------------------
# Allowed simulation types
_SIM_TYPES = {"brute_force", "credential_stuffing", "port_scan",
              "canary_breach", "all"}

_sim_lock = threading.Lock()
_sim_running = False


def _run_simulation(sim_type: str):
    """Runs the requested simulation in a background daemon thread."""
    global _sim_running
    TARGET_HOST = "127.0.0.1"
    TARGET_PORT = config.HONEYPOT_PORT

    try:
        import paramiko  # local import – graceful if missing

        def _ssh_attempt(user: str, pwd: str):
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(hostname=TARGET_HOST, port=TARGET_PORT,
                            username=user, password=pwd,
                            timeout=3, allow_agent=False, look_for_keys=False)
            except Exception:
                pass
            finally:
                ssh.close()

        def _tcp_touch():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((TARGET_HOST, TARGET_PORT))
                s.close()
            except Exception:
                pass

        def do_brute_force():
            passwords = ["123456", "password", "admin123", "root2024",
                         "toor", "letmein123", "welcome1"]
            for i, pwd in enumerate(passwords[:6]):
                _ssh_attempt("admin", pwd)
                time.sleep(0.35)

        def do_credential_stuffing():
            users = ["root", "ubuntu", "postgres", "cisco", "oracle"]
            for user in users:
                _ssh_attempt(user, "P@ssw0rd2024!")
                time.sleep(0.35)

        def do_port_scan():
            for _ in range(7):
                _tcp_touch()
                time.sleep(0.18)

        def do_canary_breach():
            cp = config.CANARY_FILE_PATH
            if not cp.exists():
                try:
                    canary.create_decoy_canary_file()
                except Exception:
                    pass
            try:
                with open(cp, "a+b") as f:
                    f.write(b" ")
            except Exception:
                pass

        if sim_type == "brute_force":
            do_brute_force()
        elif sim_type == "credential_stuffing":
            do_credential_stuffing()
        elif sim_type == "port_scan":
            do_port_scan()
        elif sim_type == "canary_breach":
            do_canary_breach()
        elif sim_type == "all":
            _ssh_attempt("support", "TestPass123")
            time.sleep(0.5)
            do_brute_force()
            time.sleep(0.5)
            do_credential_stuffing()
            time.sleep(0.5)
            do_port_scan()
            time.sleep(0.5)
            do_canary_breach()

    except Exception as exc:
        print(f"[Simulator] Error during '{sim_type}': {exc}")
    finally:
        with _sim_lock:
            _sim_running = False


@app.route("/api/simulate/<sim_type>", methods=["POST"])
@login_required
def api_simulate(sim_type: str):
    global _sim_running
    if sim_type not in _SIM_TYPES:
        return jsonify({"success": False, "error": f"Unknown simulation type '{sim_type}'. "
                        f"Allowed: {sorted(_SIM_TYPES)}"}), 400

    with _sim_lock:
        if _sim_running:
            return jsonify({"success": False, "error": "A simulation is already running."}), 429
        _sim_running = True

    t = threading.Thread(target=_run_simulation, args=(sim_type,), daemon=True)
    t.start()
    return jsonify({"success": True, "message": f"Simulation '{sim_type}' started."})


@app.route("/api/simulate/status")
@login_required
def api_simulate_status():
    return jsonify({"running": _sim_running})


# ---------------------------------------------------------------------------
# HTTP Decoy Traps — catches web bots scanning for common admin panels
# ---------------------------------------------------------------------------
_DECOY_PATHS = {
    "/wp-login.php":   ("WP_LOGIN",    "MEDIUM"),
    "/phpmyadmin":     ("PHPMYADMIN",  "MEDIUM"),
    "/.env":           ("ENV_PROBE",   "HIGH"),
    "/admin-portal":   ("ADMIN_PROBE", "MEDIUM"),
    "/.git/config":    ("GIT_PROBE",   "HIGH"),
    "/xmlrpc.php":     ("XMLRPC",      "LOW"),
    "/config.php":     ("CONFIG_PROBE","MEDIUM"),
    "/backup.zip":     ("BACKUP_PROBE","MEDIUM"),
}

def _handle_decoy_trap(path: str):
    """
    Logs a web-bot decoy trap hit into alerts + live feed, then
    returns a fake 200 response to keep the bot engaged longer.
    """
    rule_name, severity = _DECOY_PATHS.get(path, ("HTTP_TRAP", "LOW"))
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0").split(",")[0].strip()
    ua = request.headers.get("User-Agent", "Unknown")[:120]
    description = (
        f"HTTP decoy trap triggered: {request.method} {path} "
        f"from {ip} | UA: {ua}"
    )
    # Log as alert
    db.log_alert(ip, rule_name, description, severity=severity, blocked=False)

    # Inject a synthetic event into the live feed so it appears on dashboard
    event_data = {
        "ip": ip,
        "port": 80,
        "username": f"[HTTP:{rule_name}]",
        "password": path,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "country": "Web Bot",
        "city": "HTTP Trap",
        "latitude": 0.0,
        "longitude": 0.0,
        "client_version": ua,
        "triggered_rules": [{
            "rule": rule_name,
            "ip": ip,
            "description": description,
            "severity": severity,
            "blocked": False
        }]
    }
    # Broadcast without blocking request thread
    def _emit():
        with app.app_context():
            summary = db.get_analytics_summary()
            socketio.emit("new_attack", {"attack": event_data, "summary": summary})

    threading.Thread(target=_emit, daemon=True).start()

    # Return a convincing fake page (not 404) to waste bot time
    return (
        "<!DOCTYPE html><html><head><title>Login</title></head>"
        "<body><h2>Please Log In</h2>"
        "<form method='post'><input name='user' placeholder='Username'>"
        "<input type='password' name='pass' placeholder='Password'>"
        "<button type='submit'>Login</button></form></body></html>"
    ), 200, {"Content-Type": "text/html"}


# Register decoy trap routes
for _trap_path in _DECOY_PATHS:
    # Need a closure to capture path value
    def _make_trap_view(p):
        def _trap_view():
            return _handle_decoy_trap(p)
        _trap_view.__name__ = f"decoy_{p.replace('/', '_').replace('.', '_')}"
        return _trap_view
    app.add_url_rule(_trap_path, endpoint=f"trap_{_trap_path}",
                     view_func=_make_trap_view(_trap_path),
                     methods=["GET", "POST"])


# ---------------------------------------------------------------------------
# Service Orchestrator
# ---------------------------------------------------------------------------
def start_services():
    """Starts SSH Honeypot and Canary Watchdog in background daemon threads.
    Both are wrapped in try/except so restricted cloud containers never crash.
    """
    db.init_db()

    # 1. Start SSH Honeypot — optional on restricted platforms
    try:
        honeypot = HoneypotServer(
            host=config.HONEYPOT_HOST,
            port=config.HONEYPOT_PORT,
            on_event_callback=on_honeypot_event
        )
        hp_thread = threading.Thread(target=honeypot.start, daemon=True)
        hp_thread.start()
        print(f"[HoneyGuard] SSH Honeypot listening on 0.0.0.0:{config.HONEYPOT_PORT}")
    except Exception as exc:
        print(f"[HoneyGuard] WARNING: SSH Honeypot could not start (port {config.HONEYPOT_PORT}): {exc}")
        print("[HoneyGuard] Continuing without SSH honeypot — HTTP decoy traps are active.")

    # 2. Firewall setup — silently skip if not permitted (cloud containers)
    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "-p", "tcp", "--dport",
             str(config.HONEYPOT_PORT), "-j", "ACCEPT"],
            timeout=5, capture_output=True, check=True
        )
    except Exception:
        pass  # Not root or iptables not available — that's fine

    # 3. Start Canary File Watchdog
    try:
        canary.start_canary_monitor(on_breach_callback=on_canary_event)
    except Exception as exc:
        print(f"[HoneyGuard] WARNING: Canary monitor could not start: {exc}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    start_services()
    print("\n" + "=" * 60)
    print("🍯  HONEYGUARD UNIFIED SYSTEM — v2.0")
    print(f"👉  SSH Decoy Honeypot : 0.0.0.0:{config.HONEYPOT_PORT}")
    print(f"👉  Web Dashboard      : http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")
    print(f"👉  Login              : {config.DASHBOARD_USERNAME} / {config.DASHBOARD_PASSWORD}")
    print(f"👉  Auto-Block Mode    : {'DRY_RUN (Simulation)' if config.DRY_RUN else 'ACTIVE FIREWALL'}")
    print(f"👉  HTTP Decoy Traps   : {', '.join(_DECOY_PATHS)}")
    print("=" * 60 + "\n")

    socketio.run(app, host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT,
                 debug=False, allow_unsafe_werkzeug=True)
