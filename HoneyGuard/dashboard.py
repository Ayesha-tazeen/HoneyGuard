"""
HoneyGuard Live Web Dashboard & Orchestrator
Flask + Flask-SocketIO application providing real-time attack visualization,
intrusion alerts, geo-mapping, and incident response controls.
Binds strictly to 127.0.0.1 with session-based login and anti-XSS safeguards.
"""

import os
import threading
from functools import wraps
from pathlib import Path
from flask import (
    Flask, render_template, request, redirect, url_for, session, jsonify, send_file, flash
)
from flask_socketio import SocketIO
import config
import db
import blocker
import canary
import report
from honeypot import HoneypotServer

# Initialize Flask & SocketIO
app = Flask(__name__)
app.config["SECRET_KEY"] = config.DASHBOARD_SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# --- Background Services Orchestrator ---

def on_honeypot_event(data: dict):
    """Broadcasts honeypot events to connected WebSockets."""
    with app.app_context():
        # Update analytics snapshot
        summary = db.get_analytics_summary()
        socketio.emit("new_attack", {
            "attack": data,
            "summary": summary
        })

def on_canary_event(data: dict):
    """Broadcasts canary trap breaches to connected WebSockets."""
    with app.app_context():
        summary = db.get_analytics_summary()
        socketio.emit("new_canary", {
            "canary": data,
            "summary": summary
        })

# --- Web Routes ---

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if username == config.DASHBOARD_USERNAME and password == config.DASHBOARD_PASSWORD:
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("index"))
        else:
            flash("Invalid administrator credentials. Please check .env configuration.", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

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

# --- REST APIs for Dynamic UI updates ---

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
        return jsonify({"success": True, "filename": filename, "download_url": f"/download_report/{filename}"})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500

@app.route("/download_report/<filename>")
@login_required
def download_report(filename: str):
    safe_path = config.REPORTS_DIR / Path(filename).name
    if safe_path.exists():
        return send_file(safe_path, as_attachment=True)
    return "Report not found", 404

def start_services():
    """Starts Honeypot SSH server and Canary Watchdog in background daemon threads."""
    db.init_db()

    # 1. Start SSH Honeypot
    honeypot = HoneypotServer(
        host=config.HONEYPOT_HOST,
        port=config.HONEYPOT_PORT,
        on_event_callback=on_honeypot_event
    )
    hp_thread = threading.Thread(target=honeypot.start, daemon=True)
    hp_thread.start()

    # 2. Start Canary File Watchdog
    canary.start_canary_monitor(on_breach_callback=on_canary_event)

if __name__ == "__main__":
    start_services()
    print("\n" + "="*60)
    print("🍯 HONEYGUARD UNIFIED SYSTEM RUNNING")
    print(f"👉 Decoy SSH Honeypot:  0.0.0.0:{config.HONEYPOT_PORT}")
    print(f"👉 Web Admin Dashboard: http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")
    print(f"👉 Login:               {config.DASHBOARD_USERNAME} / {config.DASHBOARD_PASSWORD}")
    print(f"👉 Auto-Block Mode:     {'DRY_RUN (Simulation)' if config.DRY_RUN else 'ACTIVE FIREWALL'}")
    print("="*60 + "\n")

    # Bind strictly to 127.0.0.1 for maximum dashboard host isolation
    socketio.run(app, host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT, debug=False, allow_unsafe_werkzeug=True)
