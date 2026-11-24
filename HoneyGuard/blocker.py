"""
HoneyGuard Auto-Blocker Module
Implements cross-platform firewall blocking (Windows netsh advfirewall & Linux ufw)
with safety allowlisting and DRY_RUN mode enabled by default.
"""

import platform
import subprocess
import logging
from typing import Dict, Any
import config
import db

logger = logging.getLogger("HoneyGuard.Blocker")

def is_allowlisted(ip: str) -> bool:
    """Checks whether the given IP is protected from being blocked."""
    cleaned_ip = ip.strip()
    return (
        cleaned_ip in config.ALLOWLIST
        or cleaned_ip.startswith("127.")
        or cleaned_ip == "::1"
        or cleaned_ip == "localhost"
    )

def block_ip(ip: str, reason: str = "Automated Intrusion Detection Ban") -> Dict[str, Any]:
    """
    Executes firewall block command or simulates it if DRY_RUN is active.
    Never blocks allowlisted addresses.
    """
    if is_allowlisted(ip):
        logger.info(f"[ALLOWLIST] Skipped blocking protected IP: {ip}")
        return {"success": False, "status": "skipped", "message": f"{ip} is in the allowlist"}

    os_type = platform.system()

    if config.DRY_RUN:
        logger.warning(f"[DRY_RUN] Simulated blocking of IP {ip} (Reason: {reason})")
        db.log_blocked_ip(ip, f"[DRY_RUN] {reason}")
        return {
            "success": True,
            "status": "simulated",
            "message": f"[DRY_RUN] Simulated block on {ip}. No firewall modifications made."
        }

    try:
        if os_type == "Windows":
            # Windows Defender Firewall command
            rule_name = f"HoneyGuard_Block_{ip.replace(':', '_')}"
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}"
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.info(f"[FIREWALL] Windows rule added: {rule_name}")

        elif os_type == "Linux":
            # Linux UFW (Uncomplicated Firewall) command
            cmd = ["ufw", "deny", "from", ip, "to", "any"]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.info(f"[FIREWALL] Linux UFW rule added: deny from {ip}")

        else:
            return {"success": False, "status": "unsupported", "message": f"Unsupported OS: {os_type}"}

        db.log_blocked_ip(ip, reason)
        return {"success": True, "status": "blocked", "message": f"Successfully blocked {ip}"}

    except subprocess.CalledProcessError as err:
        logger.error(f"Firewall execution failed for {ip}: {err.stderr}")
        return {"success": False, "status": "error", "message": err.stderr}
    except Exception as exc:
        logger.error(f"Unexpected blocker error for {ip}: {exc}")
        return {"success": False, "status": "error", "message": str(exc)}

def unblock_ip(ip: str) -> Dict[str, Any]:
    """Removes a previously blocked IP from the firewall."""
    os_type = platform.system()

    if config.DRY_RUN:
        logger.info(f"[DRY_RUN] Simulated unblock on {ip}")
        with db.get_connection() as conn:
            conn.execute("UPDATE blocked_ips SET active = 0 WHERE ip = ?", (ip,))
            conn.commit()
        return {"success": True, "status": "simulated", "message": f"[DRY_RUN] Unblocked {ip}"}

    try:
        if os_type == "Windows":
            rule_name = f"HoneyGuard_Block_{ip.replace(':', '_')}"
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            subprocess.run(cmd, check=True, capture_output=True, text=True)

        elif os_type == "Linux":
            cmd = ["ufw", "delete", "deny", "from", ip]
            subprocess.run(cmd, check=True, capture_output=True, text=True)

        with db.get_connection() as conn:
            conn.execute("UPDATE blocked_ips SET active = 0 WHERE ip = ?", (ip,))
            conn.commit()

        logger.info(f"[FIREWALL] Unblocked IP {ip}")
        return {"success": True, "status": "unblocked", "message": f"Successfully unblocked {ip}"}

    except Exception as exc:
        logger.error(f"Failed to unblock {ip}: {exc}")
        return {"success": False, "status": "error", "message": str(exc)}
