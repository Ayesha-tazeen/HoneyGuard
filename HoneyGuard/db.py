"""
HoneyGuard Database Module
Handles SQLite schema creation, thread-safe connection pooling, and analytical queries.
"""

import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import config

# Re-entrant Lock to ensure SQLite concurrency and avoid deadlocks in nested calls
_db_lock = threading.RLock()

def get_connection() -> sqlite3.Connection:
    """Creates a connection with row-factory enabled."""
    conn = sqlite3.connect(str(config.DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    """Initializes the database schema with necessary tables and indexes."""
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Attacks table: logs every authentication attempt
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    client_version TEXT,
                    country TEXT DEFAULT 'Unknown',
                    city TEXT DEFAULT 'Unknown',
                    latitude REAL DEFAULT 0.0,
                    longitude REAL DEFAULT 0.0
                )
            """)

            # 2. Alerts table: logs triggered detection rules
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    blocked INTEGER DEFAULT 0
                )
            """)

            # 3. Blocked IPs table: tracks firewall bans
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE NOT NULL,
                    reason TEXT NOT NULL,
                    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    active INTEGER DEFAULT 1
                )
            """)

            # 4. Canary file access events
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS canary_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_name TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
            """)

            # Indexes for ultra-fast time-window queries in detection engine
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_attacks_ip_time ON attacks(ip, timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip)")
            
            conn.commit()

# --- Attack Logging & Queries ---

def log_attack(ip: str, port: int, username: str, password: str,
               client_version: str = "Unknown", geo: Optional[Dict[str, Any]] = None) -> int:
    """Inserts a single honeypot attack event."""
    geo = geo or {}
    country = geo.get("country", "Localhost / Internal Test" if ip in ("127.0.0.1", "localhost") else "Unknown")
    city = geo.get("city", "Local Machine" if ip in ("127.0.0.1", "localhost") else "Unknown")
    lat = float(geo.get("lat", 28.6139 if ip in ("127.0.0.1", "localhost") else 0.0))
    lon = float(geo.get("lon", 77.2090 if ip in ("127.0.0.1", "localhost") else 0.0))

    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO attacks (ip, port, username, password, client_version, country, city, latitude, longitude)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ip, port, username, password, client_version, country, city, lat, lon))
            conn.commit()
            return cursor.lastrowid

def get_recent_attacks(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recent honeypot login attempts."""
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, ip, port, username, password, timestamp, country, city, latitude, longitude
                FROM attacks
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

def count_recent_attempts(ip: str, seconds: int) -> int:
    """Counts attempts from a specific IP within the given time window."""
    cutoff = (datetime.utcnow() - timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM attacks
                WHERE ip = ? AND timestamp >= ?
            """, (ip, cutoff))
            return cursor.fetchone()[0]

def count_distinct_usernames(ip: str, seconds: int) -> int:
    """Counts unique usernames tried by an IP within the given window (Credential Stuffing)."""
    cutoff = (datetime.utcnow() - timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(DISTINCT username) FROM attacks
                WHERE ip = ? AND timestamp >= ?
            """, (ip, cutoff))
            return cursor.fetchone()[0]

# --- Alerts & Threat Level ---

def log_alert(ip: str, rule_name: str, description: str, severity: str, blocked: bool = False) -> int:
    """Logs a triggered security alert."""
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts (ip, rule_name, description, severity, blocked)
                VALUES (?, ?, ?, ?, ?)
            """, (ip, rule_name, description, severity, 1 if blocked else 0))
            conn.commit()
            return cursor.lastrowid

def get_recent_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recent alerts for the dashboard."""
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, ip, rule_name, description, severity, timestamp, blocked
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

def calculate_threat_level() -> str:
    """
    Computes overall system threat level:
    - HIGH: Any alert in last 10 minutes OR > 20 attacks in last 5 minutes OR active canary access
    - MEDIUM: Any attacks in last 10 minutes OR alerts in last 1 hour
    - LOW: Normal baseline activity
    """
    now = datetime.utcnow()
    ten_min_ago = (now - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    five_min_ago = (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    one_hour_ago = (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")

    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            # Check canary breaches
            cursor.execute("SELECT COUNT(*) FROM canary_events WHERE timestamp >= ?", (ten_min_ago,))
            canary_breaches = cursor.fetchone()[0]
            if canary_breaches > 0:
                return "HIGH"

            # Check recent alerts
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= ?", (ten_min_ago,))
            recent_alerts = cursor.fetchone()[0]
            
            # Check 5 min attack volume
            cursor.execute("SELECT COUNT(*) FROM attacks WHERE timestamp >= ?", (five_min_ago,))
            recent_attacks_5m = cursor.fetchone()[0]

            if recent_alerts > 0 or recent_attacks_5m >= 20:
                return "HIGH"

            # Medium threshold check
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= ?", (one_hour_ago,))
            alerts_1h = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM attacks WHERE timestamp >= ?", (ten_min_ago,))
            attacks_10m = cursor.fetchone()[0]

            if alerts_1h > 0 or attacks_10m > 0:
                return "MEDIUM"

            return "LOW"

# --- Blocker Database Tracking ---

def log_blocked_ip(ip: str, reason: str) -> None:
    """Records an IP address that has been banned by the firewall engine."""
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO blocked_ips (ip, reason, active)
                VALUES (?, ?, 1)
                ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, active = 1, blocked_at = CURRENT_TIMESTAMP
            """, (ip, reason))
            conn.commit()

def get_blocked_ips() -> List[Dict[str, Any]]:
    """Retrieves all currently blocked IPs."""
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, ip, reason, blocked_at, active FROM blocked_ips ORDER BY id DESC")
            return [dict(row) for row in cursor.fetchall()]

def is_ip_blocked(ip: str) -> bool:
    """Checks whether an IP is currently marked as blocked."""
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT active FROM blocked_ips WHERE ip = ? AND active = 1", (ip,))
            row = cursor.fetchone()
            return row is not None

# --- Canary Logging ---

def log_canary_event(file_name: str, event_type: str, details: str = "") -> int:
    """Records honeypot canary trap interaction."""
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO canary_events (file_name, event_type, details)
                VALUES (?, ?, ?)
            """, (file_name, event_type, details))
            conn.commit()
            return cursor.lastrowid

# --- Analytical Aggregations for Live Dashboard ---

def get_analytics_summary() -> Dict[str, Any]:
    """Generates counts, top lists, and chart series for the dashboard."""
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()

            # Total attack count
            cursor.execute("SELECT COUNT(*) FROM attacks")
            total_attacks = cursor.fetchone()[0]

            # Total alerts count
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]

            # Total blocked count
            cursor.execute("SELECT COUNT(*) FROM blocked_ips WHERE active = 1")
            total_blocked = cursor.fetchone()[0]

            # Top 5 Usernames
            cursor.execute("""
                SELECT username, COUNT(*) as count
                FROM attacks
                GROUP BY username
                ORDER BY count DESC
                LIMIT 5
            """)
            top_usernames = [dict(row) for row in cursor.fetchall()]

            # Top 5 Passwords
            cursor.execute("""
                SELECT password, COUNT(*) as count
                FROM attacks
                GROUP BY password
                ORDER BY count DESC
                LIMIT 5
            """)
            top_passwords = [dict(row) for row in cursor.fetchall()]

            # Top 5 Attacker IPs
            cursor.execute("""
                SELECT ip, country, COUNT(*) as count
                FROM attacks
                GROUP BY ip
                ORDER BY count DESC
                LIMIT 5
            """)
            top_ips = [dict(row) for row in cursor.fetchall()]

            # Attacks per minute (last 10 minutes)
            cursor.execute("""
                SELECT strftime('%H:%M', timestamp) as minute_bucket, COUNT(*) as count
                FROM attacks
                WHERE timestamp >= datetime('now', '-15 minutes')
                GROUP BY minute_bucket
                ORDER BY minute_bucket ASC
            """)
            attacks_per_min = [dict(row) for row in cursor.fetchall()]

            return {
                "total_attacks": total_attacks,
                "total_alerts": total_alerts,
                "total_blocked": total_blocked,
                "top_usernames": top_usernames,
                "top_passwords": top_passwords,
                "top_ips": top_ips,
                "attacks_per_min": attacks_per_min,
                "threat_level": calculate_threat_level()
            }
