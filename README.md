# 🍯 HoneyGuard v2.0 — Intrusion Detection & SOC Dashboard

> **High-contrast Midnight Slate SOC UI · 1-Click Attack Simulator · HTTP Decoy Traps · Cloud-Ready (Render/Railway)**

HoneyGuard is a fully-featured honeypot and intrusion detection system with a real-time Flask + SocketIO dashboard. It captures SSH brute-force attacks, credential stuffing, port scans, and canary breaches — and now also traps real web bots via HTTP Decoy endpoints when deployed to the cloud.

---

## ✨ What's New in v2.0

| Feature | Detail |
|---------|--------|
| **Midnight Slate SOC Theme** | `#0f172a` bg · `#1e293b` cards · `#334155` borders · `#f8fafc` text |
| **Bright Severity Badges** | `CRITICAL` (purple pulse) · `HIGH` (red pulse) · `MEDIUM` (amber) · `LOW` (green) |
| **Attack Breakdown Chart** | Doughnut Chart.js replacing the Leaflet map (no external tile server needed) |
| **Top Usernames/Passwords Tables** | Rank-ordered tables replacing old list items |
| **1-Click Attack Simulator** | Panel in dashboard → `POST /api/simulate/<type>` (Brute Force · Cred Stuffing · Port Scan · Canary · All) |
| **HTTP Decoy Traps** | `/wp-login.php`, `/phpmyadmin`, `/.env`, `/admin-portal`, `/.git/config` etc. hooked into the live feed |
| **Cloud-Aware Binding** | Binds `0.0.0.0:$PORT` on Render/Railway, `127.0.0.1:5000` locally |
| **Gunicorn + Dockerfile** | Production-grade WSGI setup with eventlet worker |
| **Graceful SSH Fallback** | SSH port 2222 and firewall commands wrapped in `try/except` — cloud containers never crash |

---

## 📁 Project Structure

```
HoneyGuard/
├── HoneyGuard/
│   ├── dashboard.py          # Flask app + REST APIs + Simulator + HTTP Traps
│   ├── config.py             # Cloud-aware configuration
│   ├── db.py                 # SQLite database layer
│   ├── honeypot.py           # Paramiko SSH honeypot server
│   ├── rules.py              # Brute-Force / CredStuffing / PortScan detection
│   ├── blocker.py            # Firewall auto-block (iptables / dry-run)
│   ├── canary.py             # Canary file watchdog
│   ├── alerts.py             # Telegram alert integration
│   ├── report.py             # PDF report generator
│   ├── test_attack.py        # CLI attack simulator (unchanged, still works)
│   ├── requirements.txt      # Python dependencies
│   ├── .env.example          # Environment variable template
│   ├── templates/
│   │   ├── index.html        # Main SOC dashboard (Chart.js + Simulator panel)
│   │   └── login.html        # Admin login page
│   └── static/
│       ├── css/style.css     # Midnight Slate SOC theme
│       └── js/dashboard.js   # Real-time WebSocket client (textContent Anti-XSS)
├── Dockerfile                # Multi-stage Docker build
├── render.yaml               # Render.com deployment config
└── README.md                 # This file
```

---

## 🚀 Quick Start (Local)

```bash
# 1. Clone & enter
cd HoneyGuard/HoneyGuard

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure (copy .env.example and edit)
copy .env.example .env

# 5. Run
python dashboard.py
```

Dashboard → **http://127.0.0.1:5000** · Default login: `admin` / `honeyguard_admin`

---

## 🔥 Attack Simulator

### Via Dashboard (1-Click)
Open the **Attack Simulator** panel at the bottom of the dashboard. Click any button:

| Button | What it does |
|--------|-------------|
| **Brute Force** | 6 rapid SSH attempts on `127.0.0.1:2222` |
| **Cred Stuffing** | 5 distinct usernames via SSH |
| **Port Scan** | 7 rapid TCP probes |
| **Canary Breach** | Touches `canary_files/passwords.xlsx` |
| **All Tests** | Runs all four sequentially |

### Via CLI (unchanged)
```bash
python test_attack.py          # Interactive menu
python test_attack.py --all    # Run all tests
```

### Via API
```bash
curl -X POST http://127.0.0.1:5000/api/simulate/brute_force \
     -H "Cookie: session=<your_session>"
```

---

## 🌐 HTTP Decoy Traps

When deployed to the cloud (where port 2222 is blocked), these paths catch real web bots:

| Path | Rule | Severity |
|------|------|----------|
| `/wp-login.php` | `WP_LOGIN` | MEDIUM |
| `/phpmyadmin` | `PHPMYADMIN` | MEDIUM |
| `/.env` | `ENV_PROBE` | HIGH |
| `/admin-portal` | `ADMIN_PROBE` | MEDIUM |
| `/.git/config` | `GIT_PROBE` | HIGH |
| `/xmlrpc.php` | `XMLRPC` | LOW |
| `/config.php` | `CONFIG_PROBE` | MEDIUM |
| `/backup.zip` | `BACKUP_PROBE` | MEDIUM |

All hits appear in the **live feed** and **alerts panel** immediately.

---

## ☁️ Cloud Deployment

### Render.com (Free Tier)

1. Push repo to GitHub
2. Create a new **Web Service** → connect repo
3. Set **Root Directory** to `HoneyGuard`
4. Set **Build Command**: `pip install -r requirements.txt`
5. Set **Start Command**: `gunicorn --worker-class eventlet --workers 1 --bind 0.0.0.0:$PORT "dashboard:app"`
6. Add environment variables (`DASHBOARD_PASSWORD`, `DASHBOARD_SECRET_KEY`, `DRY_RUN=True`)

Or use the included `render.yaml` for one-click deploy.

### Docker

```bash
# Build from repo root
docker build -t honeyguard .

# Run locally
docker run -p 5000:5000 \
  -e DASHBOARD_PASSWORD=mysecret \
  -e DASHBOARD_SECRET_KEY=mysecretkey \
  honeyguard
```

---

## 🔒 Security Design

- **Anti-XSS**: All attacker-supplied values (usernames, passwords, IPs, user-agents) are injected via `textContent` only — never `innerHTML`. This guarantees immunity against XSS from attacker payloads.
- **Session-based auth**: Dashboard protected by Flask session login.
- **Allowlist**: `127.0.0.1`, `::1`, `localhost` are never auto-blocked.
- **DRY_RUN default**: Firewall blocking is simulation-only by default.

---

## 📊 Dashboard Features

| Panel | Description |
|-------|-------------|
| Metric Cards | Threat Level · Total Attacks · Security Alerts · Blocked IPs |
| Attack Intensity | Line chart (Chart.js) — attacks per minute, last 15 min |
| Attack Breakdown | Doughnut chart — by rule type (Brute/Cred/Port/Canary/HTTP) |
| Live Feed | Real-time table of SSH + HTTP trap events |
| Alerts Panel | Rule engine alerts with severity badges |
| Top Usernames | Ranked table of most-targeted usernames |
| Top Passwords | Ranked table of most-tried passwords |
| Firewall Blocklist | Active blocks with 1-click Unblock |
| Simulator | 1-click attack triggers with live log |

---

## ⚙️ Detection Rules

| Rule | Trigger |
|------|---------|
| **BRUTE_FORCE** | ≥5 login attempts from same IP within 60 s |
| **CREDENTIAL_STUFFING** | ≥4 distinct usernames from same IP within 120 s |
| **PORT_SCAN** | ≥5 TCP connection touches within 30 s |
| **CANARY_BREACH** | Any access/modification of `canary_files/passwords.xlsx` |
| **HTTP_TRAP_*** | Any request to decoy web paths |

---

## ⚠️ Ethical & Legal Notice

This tool is intended **strictly for educational purposes and authorized security lab environments only**.

- Run only on systems you own or have explicit written permission to monitor.
- Never execute attack simulations against external networks.
- The `test_attack.py` and dashboard simulator target **127.0.0.1 only**.
