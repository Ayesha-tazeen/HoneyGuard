# 🍯 HoneyGuard: A Real-Time Honeypot-Based Intrusion Detection and Auto-Response System

**BCA Final-Year Minor Project**  
*Designed for small businesses, medical clinics, coaching centres, and academic computer laboratories.*

---

## ⚠️ Important Safety & Ethical Disclosure
> **Educational & Defensive Use Only:** This honeypot decoy system is designed exclusively for deployment in authorized private networks or virtual test environments (e.g., local VMs). The provided attack simulation tool (`test_attack.py`) is hardcoded to target only your local loopback address (`127.0.0.1`). **Never deploy attack scripts against external hosts or networks without explicit written permission.**

---

## 📌 Project Overview
Small organizations—such as coaching institutes, outpatient clinics, and accounting offices—frequently run exposed servers (e.g., CCTV NVRs, tally servers, database backups) without dedicated Security Operations Center (SOC) personnel. 

**HoneyGuard** solves this dilemma by deploying a lightweight, high-interaction decoy SSH service. It deceives external attackers, captures credentials, evaluates threat patterns via a real-time rule engine, notifies administrators via Telegram, automatically issues firewall bans (with safe Dry-Run mode), traps lateral movement using canary files, and displays real-time threat intelligence on a live web dashboard.

---

## 🏗️ System Architecture

```text
       +-------------------------------------------------------------+
       |                   INTRUDER / BOTNET                         |
       +-------------------------------------------------------------+
                                     |
               (Attempting SSH Logins on Port 2222)
                                     v
       +-------------------------------------------------------------+
       |             HONEYGUARD DECOY SSH SERVER                     |
       |  - Paramiko Server Interface                                |
       |  - ALWAYS Rejects Password Auth (AUTH_FAILED)               |
       |  - Zero Shell / PTY / Command Execution Permitted           |
       +-------------------------------------------------------------+
                                     |
                 (Intercepts IP, User, Password, Time)
                                     v
       +-------------------------------------------------------------+
       |              REAL-TIME DETECTION RULE ENGINE                |
       |  - Brute Force: >= 5 attempts in 60s                        |
       |  - Credential Stuffing: >= 4 distinct users in 120s         |
       |  - Port Scan: >= 5 raw connections in 30s                   |
       +-------------------------------------------------------------+
                     |                       |               |
                     v                       v               v
           +--------------------+  +------------------+  +-------------------+
           | TELEGRAM BOT ALERT |  |  FIREWALL BLOCK  |  |  CANARY MONITOR   |
           | Instant Push Alert |  | Windows: netsh   |  | passwords.xlsx    |
           | to Admin Phone     |  | Linux:   ufw     |  | (Watchdog Trap)   |
           | (.env Configured)  |  | (DRY_RUN Safe)   |  |                   |
           +--------------------+  +------------------+  +-------------------+
                     \                       |               /
                      \                      v              /
                       +-----------------------------------+
                       |    SQLITE3 THREAT DATABASE        |
                       |  (Attacks, Alerts, Bans, Canaries)|
                       +-----------------------------------+
                                         |
                                         v
       +-------------------------------------------------------------+
       |            SOC WEB DASHBOARD (Flask + Socket.IO)            |
       |  - Bound strictly to 127.0.0.1:5000                         |
       |  - Anti-XSS Architecture (textContent DOM Rendering Only)  |
       |  - Live Attack Feed & Attempts/Min Line Chart (Chart.js)    |
       |  - Global Attack Origin Map (Leaflet.js + Offline GeoIP)   |
       |  - Executive PDF Security Incident Reports (ReportLab)      |
       +-------------------------------------------------------------+
```

---

## 🛠️ Technology Stack
* **Language:** Python 3.10+
* **Decoy SSH Engine:** Paramiko
* **Storage:** SQLite3 (Thread-safe concurrency with `threading.RLock`)
* **Web SOC Dashboard:** Flask, Flask-SocketIO (WebSocket events)
* **Visualizations:** Chart.js (Line graphs), Leaflet.js (Attacker location map)
* **Threat Notification:** Telegram Bot API (`requests`)
* **Host Defense / Auto-Response:** Windows Defender Firewall (`netsh advfirewall`) & Linux (`ufw`)
* **Canary Trap:** Python `watchdog` & `openpyxl`
* **Audit & Reporting:** ReportLab PDF Engine

---

## 📁 Project Directory Structure
```text
HoneyGuard/
├── .env.example          # Sample environment secrets template
├── .env                  # Active credentials (ignored by git)
├── .gitignore            # Git exclusion rules
├── requirements.txt      # Python dependencies
├── config.py             # Central configuration, rule windows & thresholds
├── db.py                 # SQLite database schema, queries, threat level
├── honeypot.py           # Paramiko decoy SSH server engine
├── rules.py              # Real-time intrusion detection rule engine
├── alerts.py             # Telegram alert dispatcher (with local mock mode)
├── blocker.py            # Windows/Linux firewall auto-blocker with allowlist
├── canary.py             # Fake passwords.xlsx decoy generator & watchdog
├── report.py             # ReportLab PDF threat summary generator
├── dashboard.py          # Unified Flask-SocketIO SOC dashboard server
├── templates/
│   ├── login.html        # Secure dashboard login screen
│   └── index.html        # SOC control panel, live charts, feeds & map
├── static/
│   ├── css/style.css     # Dark mode SOC theme styling
│   └── js/dashboard.js   # Real-time WebSocket handlers & Anti-XSS rendering
└── test_attack.py        # Safe local intrusion simulation test suite
```

---

## 🚀 Setup & Installation (Windows PowerShell / CMD)

### 1. Clone or Open the Workspace
```powershell
cd HoneyGuard
```

### 2. Create and Activate Virtual Environment (Optional but recommended)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Configure Environment
A default `.env` file is pre-populated. To receive live Telegram alerts on your phone:
1. Talk to `@BotFather` on Telegram to create a bot and get a `TELEGRAM_BOT_TOKEN`.
2. Talk to `@userinfobot` to get your numerical `TELEGRAM_CHAT_ID`.
3. Open `.env` and set:
   ```ini
   TELEGRAM_BOT_TOKEN=123456789:ABCdefGhIJKlmNoPQRstuVWXyz
   TELEGRAM_CHAT_ID=987654321
   TELEGRAM_ENABLED=True
   ```
*(If left disabled, HoneyGuard automatically switches to Mock Console Mode, which prints realistic formatted alerts to your terminal—ideal for viva demos!)*

---

## 🖥️ Running HoneyGuard

### Step 1: Start HoneyGuard Unified Server
Open your first terminal window and run:
```powershell
python dashboard.py
```
* **Decoy SSH Honeypot:** Active on `0.0.0.0:2222`
* **Canary Trap Watchdog:** Active on `canary_files/passwords.xlsx`
* **SOC Admin Dashboard:** Accessible at `http://127.0.0.1:5000`

### Step 2: Access SOC Dashboard
1. Open your browser and navigate to: **`http://127.0.0.1:5000`**
2. Log in using default credentials:
   * **Username:** `admin`
   * **Password:** `honeyguard_admin`

---

## 🧪 Simulating Attacks (Viva Demonstration)

Open a **second terminal** window while the dashboard is running:
```powershell
python test_attack.py
```
You will see the interactive attack menu:
```text
===========================================================
🍯 HONEYGUARD ATTACK SIMULATOR (VIVA & LAB TESTING)
===========================================================
Target: 127.0.0.1 (Local Decoy Only)
Select an intrusion test:
  [1] Single SSH Auth Check (Standard Rejection)
  [2] Simulate Brute-Force Attack (6 Rapid Passwords)
  [3] Simulate Credential Stuffing (5 Distinct Usernames)
  [4] Simulate Rapid Port Probe / Sweep
  [5] Simulate Canary Honeytoken Breach (passwords.xlsx)
  [6] Run ALL Tests Sequentially
  [0] Exit
===========================================================
```

### What Happens in Each Test:
* **Option 1 (Single Auth):** Verifies the decoy intercepts credentials and immediately rejects authentication with zero shell access.
* **Option 2 (Brute Force):** Fires 6 attempts in < 10 seconds. Triggers `BRUTE_FORCE` rule, raises `HIGH` alert, updates the live dashboard via WebSockets, and invokes `blocker.py`.
* **Option 3 (Credential Stuffing):** Cycles through `root`, `ubuntu`, `postgres`, `cisco`, `oracle`. Triggers `CREDENTIAL_STUFFING` rule.
* **Option 4 (Port Scan):** Rapidly opens/closes 6 TCP sockets. Triggers `PORT_SCAN` rule and raises a `MEDIUM` severity alert.
* **Option 5 (Canary Breach):** Touches the decoy `canary_files/passwords.xlsx` file. Triggers an instant `CRITICAL` breach alert and popup warning.

---

## 🔒 Security Measures Implemented
1. **Strict Anti-XSS Safeguards:** Attackers often inject payloads like `<script>alert('pwned')</script>` or `<img src=x onerror=...>` as usernames/passwords. In `static/js/dashboard.js`, all dynamic content is injected strictly using `element.textContent`, never `innerHTML`.
2. **Decoy Shell Denial:** Paramiko's `check_channel_request`, `check_channel_pty_request`, and `check_channel_shell_request` are overridden to return `OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED` and `False`. Attackers cannot execute commands or browse files.
3. **Loopback Dashboard Binding:** Flask binds to `127.0.0.1`, ensuring the management dashboard cannot be accessed from external WAN/LAN interfaces without proper admin access.
4. **Firewall Dry-Run & Protection Allowlist:** `DRY_RUN=True` ensures student testers do not accidentally alter their machine's firewall rules during experimentation. The critical allowlist (`127.0.0.1`, `localhost`, `::1`) guarantees you can never block yourself.
5. **No Hardcoded Secrets:** Credentials, API tokens, and thresholds are isolated in `.env` and `config.py`.

---

## 📄 Generating PDF Threat Reports
Click the **"Generate PDF Report"** button on the dashboard navbar, or call:
```powershell
python -c "import report; print(report.generate_pdf_report())"
```
The report is generated in `reports/` with an executive summary, threat level assessment, top credentials targeted, and hardening recommendations.
#   H o n e y G u a r d  
 