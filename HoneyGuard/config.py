"""
HoneyGuard Configuration Module
Contains all system settings, thresholds, and environment variables.
Supports both local (127.0.0.1) and cloud (0.0.0.0:$PORT) deployment.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base Directory of the Project
BASE_DIR = Path(__file__).resolve().parent

# Load .env file
load_dotenv(BASE_DIR / ".env")

# --- HONEYPOT SERVER SETTINGS ---
HONEYPOT_HOST = os.getenv("HONEYPOT_HOST", "0.0.0.0")
HONEYPOT_PORT = int(os.getenv("HONEYPOT_PORT", "2222"))  # 2222 avoids needing Admin/Root privilege
SSH_BANNER = os.getenv("SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
HOST_KEY_PATH = BASE_DIR / "host_rsa.key"

# --- DATABASE SETTINGS ---
DB_PATH = BASE_DIR / "honeyguard.db"

# --- INTRUSION DETECTION RULE THRESHOLDS ---
# 1. Brute Force Rule: >= X attempts from same IP within Y seconds
BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
BRUTE_FORCE_WINDOW = int(os.getenv("BRUTE_FORCE_WINDOW", "60"))  # in seconds

# 2. Credential Stuffing Rule: >= X distinct usernames from same IP within Y seconds
CRED_STUFFING_THRESHOLD = int(os.getenv("CRED_STUFFING_THRESHOLD", "4"))
CRED_STUFFING_WINDOW = int(os.getenv("CRED_STUFFING_WINDOW", "120"))  # in seconds

# 3. Port Scan / Quick Sweep Rule: >= X connection touches within Y seconds
PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", "5"))
PORT_SCAN_WINDOW = int(os.getenv("PORT_SCAN_WINDOW", "30"))  # in seconds

# --- AUTO-BLOCKER FIREWALL SETTINGS ---
# DRY_RUN is True by default for safe student testing!
DRY_RUN = os.getenv("DRY_RUN", "True").strip().lower() in ("true", "1", "yes")

# Critical Allowlist: Addresses that must NEVER be blocked
ALLOWLIST = [
    "127.0.0.1",
    "::1",
    "localhost"
]

# --- CANARY FILE SETTINGS ---
CANARY_DIR = BASE_DIR / "canary_files"
CANARY_FILE_PATH = CANARY_DIR / "passwords.xlsx"

# --- TELEGRAM ALERT SETTINGS ---
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
TELEGRAM_ENABLED = os.getenv("TELEGRAM_ENABLED", "False").strip().lower() in ("true", "1", "yes")

# --- WEB DASHBOARD SETTINGS ---
# Cloud-aware binding: use 0.0.0.0 when PORT env var is set (Render/Railway),
# otherwise bind to 127.0.0.1 for local security.
_port_env = os.getenv("PORT", "").strip()
if _port_env:
    DASHBOARD_HOST = "0.0.0.0"
    DASHBOARD_PORT = int(_port_env)
else:
    DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "127.0.0.1")
    DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "5000"))

DASHBOARD_SECRET_KEY = os.getenv("DASHBOARD_SECRET_KEY", "honeyguard_super_secret_session_key_2026")
DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "honeyguard_admin")

# --- REPORT SETTINGS ---
REPORTS_DIR = BASE_DIR / "reports"
