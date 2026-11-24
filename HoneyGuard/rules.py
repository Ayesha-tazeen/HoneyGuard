"""
HoneyGuard Intrusion Detection Rule Engine
Monitors authentication events in real time and triggers alerts and auto-blocking
when thresholds are breached.
"""

import time
import logging
from collections import defaultdict
from typing import Dict, List, Any, Optional
import config
import db
import alerts
import blocker

logger = logging.getLogger("HoneyGuard.Rules")

# In-memory connection tracker for Port Scanning detection
# Format: { ip: [timestamp1, timestamp2, ...] }
_connection_history = defaultdict(list)

# Cooldown tracker to prevent repeated alert floods within 30 seconds
# Format: { (ip, rule_name): last_alert_timestamp }
_alert_cooldowns: Dict[tuple, float] = {}

def is_cooling_down(ip: str, rule_name: str, cooldown_seconds: int = 30) -> bool:
    """Checks whether an alert for this rule/IP was triggered very recently."""
    now = time.time()
    key = (ip, rule_name)
    last_time = _alert_cooldowns.get(key, 0)
    if now - last_time < cooldown_seconds:
        return True
    _alert_cooldowns[key] = now
    return False

def record_raw_connection(ip: str) -> Optional[Dict[str, Any]]:
    """
    Tracks raw TCP socket connections to detect port scans / network sweeps.
    Called when a client initiates a connection to the honeypot port.
    """
    now = time.time()
    # Clean up timestamps older than PORT_SCAN_WINDOW
    window = config.PORT_SCAN_WINDOW
    _connection_history[ip] = [t for t in _connection_history[ip] if now - t <= window]
    _connection_history[ip].append(now)

    count = len(_connection_history[ip])
    if count >= config.PORT_SCAN_THRESHOLD:
        if not is_cooling_down(ip, "PORT_SCAN", cooldown_seconds=60):
            description = (
                f"Rapid port scan/probe detected: {count} connection touches "
                f"within {window} seconds on honeypot port {config.HONEYPOT_PORT}."
            )
            # Block the scanning IP
            block_res = blocker.block_ip(ip, reason="Port scan activity")
            blocked = block_res.get("success", False)

            # Record alert in DB
            db.log_alert(ip, "PORT_SCAN", description, severity="MEDIUM", blocked=blocked)

            # Send Telegram alert
            alerts.send_telegram_alert(
                rule_name="PORT_SCAN",
                ip=ip,
                description=description,
                severity="MEDIUM",
                blocked=blocked
            )

            return {
                "rule": "PORT_SCAN",
                "ip": ip,
                "description": description,
                "severity": "MEDIUM",
                "blocked": blocked
            }

    return None

def evaluate_login(ip: str, username: str, password: str) -> List[Dict[str, Any]]:
    """
    Evaluates an authentication attempt against Intrusion Detection rules:
    1. Brute Force (rapid attempts from single IP)
    2. Credential Stuffing (multiple distinct usernames tried by single IP)
    """
    triggered_rules = []

    # --- RULE 1: BRUTE FORCE DETECTION ---
    bf_window = config.BRUTE_FORCE_WINDOW
    bf_threshold = config.BRUTE_FORCE_THRESHOLD
    recent_attempts = db.count_recent_attempts(ip, bf_window)

    if recent_attempts >= bf_threshold:
        if not is_cooling_down(ip, "BRUTE_FORCE"):
            description = (
                f"Brute force SSH attack detected: {recent_attempts} login attempts "
                f"from {ip} within {bf_window} seconds."
            )
            block_res = blocker.block_ip(ip, reason="SSH Brute Force Flood")
            blocked = block_res.get("success", False)

            db.log_alert(ip, "BRUTE_FORCE", description, severity="HIGH", blocked=blocked)
            alerts.send_telegram_alert("BRUTE_FORCE", ip, description, severity="HIGH", blocked=blocked)

            triggered_rules.append({
                "rule": "BRUTE_FORCE",
                "ip": ip,
                "description": description,
                "severity": "HIGH",
                "blocked": blocked
            })

    # --- RULE 2: CREDENTIAL STUFFING DETECTION ---
    cs_window = config.CRED_STUFFING_WINDOW
    cs_threshold = config.CRED_STUFFING_THRESHOLD
    distinct_users = db.count_distinct_usernames(ip, cs_window)

    if distinct_users >= cs_threshold:
        if not is_cooling_down(ip, "CREDENTIAL_STUFFING"):
            description = (
                f"Credential stuffing attack detected: {distinct_users} distinct usernames "
                f"tested from {ip} within {cs_window} seconds (latest: '{username}')."
            )
            block_res = blocker.block_ip(ip, reason="SSH Credential Stuffing")
            blocked = block_res.get("success", False)

            db.log_alert(ip, "CREDENTIAL_STUFFING", description, severity="HIGH", blocked=blocked)
            alerts.send_telegram_alert("CREDENTIAL_STUFFING", ip, description, severity="HIGH", blocked=blocked)

            triggered_rules.append({
                "rule": "CREDENTIAL_STUFFING",
                "ip": ip,
                "description": description,
                "severity": "HIGH",
                "blocked": blocked
            })

    return triggered_rules
