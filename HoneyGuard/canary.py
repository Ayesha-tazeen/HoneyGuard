"""
HoneyGuard Canary Trap Module
Creates a realistic decoy 'passwords.xlsx' and monitors it in real-time.
Any access, modification, or tampering raises an immediate CRITICAL intrusion alert.
"""

import os
import time
import logging
from pathlib import Path
from typing import Optional, Callable
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
import openpyxl
import config
import db
import alerts

logger = logging.getLogger("HoneyGuard.Canary")

def create_decoy_canary_file() -> Path:
    """Generates the fake passwords.xlsx spreadsheet if it doesn't already exist."""
    config.CANARY_DIR.mkdir(parents=True, exist_ok=True)
    canary_path = config.CANARY_FILE_PATH

    if not canary_path.exists():
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Confidential Logins"

        # Headers
        headers = ["Asset / Service", "Host / URL", "Username", "Password", "Sensitivity", "Notes"]
        ws.append(headers)

        # Realistic Decoy Credentials
        fake_rows = [
            ["Primary Active Directory", "192.168.1.10", "ad_admin", "P@ssw0rd2026!#", "CRITICAL", "Domain Controller backup"],
            ["CCTV NVR Gateway", "192.168.1.55:8000", "cctv_master", "Hikvision#8899", "HIGH", "Server room cameras"],
            ["Finance & Tally Server", "192.168.1.100", "sa_payroll", "TallyDb$ecure!2026", "CRITICAL", "Accounting ledger"],
            ["AWS Cloud Root Console", "console.aws.amazon.com", "devops_root", "AKIA_M0CK_KEY_9921", "CRITICAL", "Disaster recovery only"],
            ["Main Gateway Firewall", "192.168.1.1", "pfsense_admin", "PfSense$ecure#", "HIGH", "Clinic / Lab border router"]
        ]
        for row in fake_rows:
            ws.append(row)

        wb.save(canary_path)
        logger.info(f"Decoy canary file created at: {canary_path}")

    return canary_path

class CanaryEventHandler(FileSystemEventHandler):
    """Watches the canary directory for access or modification events."""
    def __init__(self, on_breach_callback: Optional[Callable] = None):
        super().__init__()
        self.callback = on_breach_callback
        self.last_trigger_time = 0.0

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory and Path(event.src_path).name == config.CANARY_FILE_PATH.name:
            self._handle_breach("FILE_MODIFIED", event.src_path)

    def on_deleted(self, event: FileSystemEvent):
        if not event.is_directory and Path(event.src_path).name == config.CANARY_FILE_PATH.name:
            self._handle_breach("FILE_DELETED", event.src_path)

    def on_moved(self, event: FileSystemEvent):
        if Path(event.src_path).name == config.CANARY_FILE_PATH.name or Path(event.dest_path).name == config.CANARY_FILE_PATH.name:
            self._handle_breach("FILE_MOVED", event.src_path)

    def _handle_breach(self, event_type: str, file_path: str):
        now = time.time()
        # Suppress duplicates within 3 seconds
        if now - self.last_trigger_time < 3.0:
            return
        self.last_trigger_time = now

        file_name = Path(file_path).name
        description = (
            f"CRITICAL HONEYTOKEN BREACH: Canary file '{file_name}' was accessed or tampered with "
            f"(Event: {event_type})! Intruder has discovered decoy directory."
        )

        logger.critical(description)

        # Log event in DB
        db.log_canary_event(file_name, event_type, details=description)
        db.log_alert("127.0.0.1", "CANARY_BREACH", description, severity="CRITICAL", blocked=False)

        # Send Telegram alert immediately
        alerts.send_telegram_alert(
            rule_name="CANARY_TRAP_BREACH",
            ip="Local Host / Intranet",
            description=description,
            severity="CRITICAL",
            blocked=False
        )

        # Notify dashboard callback if registered
        if self.callback:
            try:
                self.callback({
                    "rule": "CANARY_BREACH",
                    "file_name": file_name,
                    "event_type": event_type,
                    "description": description,
                    "severity": "CRITICAL"
                })
            except Exception as e:
                logger.error(f"Error in canary breach callback: {e}")

def start_canary_monitor(on_breach_callback: Optional[Callable] = None) -> Observer:
    """Initializes decoy file and starts background watchdog observer."""
    create_decoy_canary_file()
    event_handler = CanaryEventHandler(on_breach_callback)
    observer = Observer()
    observer.schedule(event_handler, path=str(config.CANARY_DIR), recursive=False)
    observer.daemon = True
    observer.start()
    logger.info(f"Canary file watchdog active on {config.CANARY_DIR}")
    return observer
