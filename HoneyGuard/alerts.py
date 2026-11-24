"""
HoneyGuard Alerting Module
Handles Telegram Bot notifications with fallback logging for local viva demos.
"""

import logging
from datetime import datetime
from typing import Dict, Any
import requests
import config

logger = logging.getLogger("HoneyGuard.Alerts")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def send_telegram_alert(rule_name: str, ip: str, description: str, severity: str = "HIGH", blocked: bool = False) -> bool:
    """
    Sends an immediate security alert to Telegram, or prints a mock message if disabled.
    """
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    action_str = "BLOCKED (Firewall)" if blocked else ("SIMULATED (DRY_RUN)" if config.DRY_RUN else "MONITORED ONLY")

    message = (
        f"🚨 *HONEYGUARD SECURITY ALERT* 🚨\n\n"
        f"🛡️ *Rule Triggered:* `{rule_name}`\n"
        f"🌐 *Attacker IP:* `{ip}`\n"
        f"⚠️ *Severity:* *{severity.upper()}*\n"
        f"🕒 *Timestamp:* `{now_str}`\n"
        f"🔒 *Action Taken:* `{action_str}`\n\n"
        f"📝 *Details:*\n{description}\n"
    )

    if not config.TELEGRAM_ENABLED or not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID:
        print("\n" + "="*50)
        print("🔔 [TELEGRAM ALERT DISPATCH - LOCAL/MOCK MODE]")
        print(f"Rule:     {rule_name}")
        print(f"IP:       {ip}")
        print(f"Severity: {severity}")
        print(f"Action:   {action_str}")
        print(f"Details:  {description}")
        print("="*50 + "\n")
        return True

    telegram_url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": config.TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(telegram_url, json=payload, timeout=3.0)
        if response.status_code == 200:
            logger.info("Telegram notification delivered successfully.")
            return True
        else:
            logger.warning(f"Telegram API returned code {response.status_code}: {response.text}")
            return False
    except Exception as exc:
        logger.error(f"Failed to transmit Telegram alert: {exc}")
        return False
