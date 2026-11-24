/**
 * HoneyGuard Live SOC Dashboard Client — v2.0
 * Real-time event handling via WebSockets (Socket.IO).
 *
 * CRITICAL SECURITY SAFEGUARD (Anti-XSS):
 * ALL attacker-supplied strings (usernames, passwords, IPs, user-agents)
 * are injected ONLY via `textContent` / DOM node construction — NEVER
 * via innerHTML or template literals inserted into the DOM. This guarantees
 * immunity against Cross-Site Scripting regardless of attacker payload.
 */

document.addEventListener("DOMContentLoaded", () => {

    // ── Helpers ──────────────────────────────────────────────────
    function safeText(val, fallback = "—") {
        return (val !== undefined && val !== null && val !== "") ? String(val) : fallback;
    }

    function createSafeCell(text, className = "") {
        const td = document.createElement("td");
        td.textContent = safeText(text);
        if (className) td.className = className;
        return td;
    }

    function severityBadge(sev) {
        const s = (sev || "LOW").toUpperCase();
        const span = document.createElement("span");
        span.className = `badge-severity sev-${s}`;
        span.textContent = s;
        return span;
    }

    // ── 1. Attack Intensity Line Chart ───────────────────────────
    const attackCtx = document.getElementById("attackChart");
    let attackChart = null;
    if (attackCtx) {
        attackChart = new Chart(attackCtx.getContext("2d"), {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "Attempts / Min",
                    data: [],
                    borderColor: "#38bdf8",
                    backgroundColor: "rgba(56,189,248,0.10)",
                    borderWidth: 2,
                    tension: 0.35,
                    fill: true,
                    pointRadius: 3,
                    pointBackgroundColor: "#38bdf8"
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: "#334155" },
                        ticks: { color: "#cbd5e1", precision: 0 }
                    },
                    x: {
                        grid: { color: "#334155" },
                        ticks: { color: "#94a3b8", maxTicksLimit: 8 }
                    }
                },
                plugins: {
                    legend: { labels: { color: "#f8fafc" } }
                }
            }
        });
    }

    // ── 2. Attack Breakdown Doughnut Chart ───────────────────────
    const breakdownCtx = document.getElementById("breakdownChart");
    let breakdownChart = null;
    if (breakdownCtx) {
        breakdownChart = new Chart(breakdownCtx.getContext("2d"), {
            type: "doughnut",
            data: {
                labels: ["Brute Force", "Cred Stuffing", "Port Scan", "Canary", "HTTP Traps", "Other"],
                datasets: [{
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: [
                        "#ef4444", "#f97316", "#eab308",
                        "#a855f7", "#38bdf8", "#64748b"
                    ],
                    borderColor: "#1e293b",
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "62%",
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { color: "#cbd5e1", padding: 10, font: { size: 11 } }
                    }
                }
            }
        });
    }

    // ── Build breakdown counts from alerts ──────────────────────
    function updateBreakdownChart(alerts) {
        if (!breakdownChart || !alerts) return;
        const counts = { BRUTE_FORCE: 0, CREDENTIAL_STUFFING: 0, PORT_SCAN: 0,
                         CANARY_BREACH: 0, HTTP: 0, OTHER: 0 };
        alerts.forEach(a => {
            const r = (a.rule_name || a.rule || "").toUpperCase();
            if (r.includes("BRUTE"))       counts.BRUTE_FORCE++;
            else if (r.includes("CRED"))   counts.CREDENTIAL_STUFFING++;
            else if (r.includes("PORT"))   counts.PORT_SCAN++;
            else if (r.includes("CANARY")) counts.CANARY_BREACH++;
            else if (r.includes("HTTP") || r.includes("WP") || r.includes("ENV") ||
                     r.includes("ADMIN") || r.includes("GIT") || r.includes("CONFIG") ||
                     r.includes("BACKUP") || r.includes("XMLRPC") || r.includes("PROBE"))
                                           counts.HTTP++;
            else                           counts.OTHER++;
        });
        breakdownChart.data.datasets[0].data = [
            counts.BRUTE_FORCE, counts.CREDENTIAL_STUFFING,
            counts.PORT_SCAN, counts.CANARY_BREACH, counts.HTTP, counts.OTHER
        ];
        breakdownChart.update("none");
    }

    // ── 3. Live Attack Feed (textContent Anti-XSS) ───────────────
    function prependAttackRow(att) {
        const tbody = document.getElementById("attackFeedBody");
        if (!tbody) return;
        const tr = document.createElement("tr");
        tr.className = "row-new";

        const timeStr = att.timestamp
            ? String(att.timestamp).substring(11, 19)
            : new Date().toLocaleTimeString();

        tr.appendChild(createSafeCell(timeStr, "text-muted-soc fs-8"));
        tr.appendChild(createSafeCell(att.ip, "fw-semibold text-info font-monospace"));

        const locTd = createSafeCell(`${att.city || "Unknown"}, ${att.country || "Unknown"}`);
        locTd.style.color = "#ffffff";
        locTd.style.fontSize = "0.8rem";
        tr.appendChild(locTd);

        // Attacker payload — textContent ONLY (Anti-XSS)
        tr.appendChild(createSafeCell(att.username, "text-warning font-monospace fs-8"));
        tr.appendChild(createSafeCell(att.password, "font-monospace fs-8"));

        // Status badge
        const tdStatus = document.createElement("td");
        const badge = document.createElement("span");
        const isHttp = String(att.username || "").startsWith("[HTTP:");
        badge.className = isHttp
            ? "badge bg-purple-subtle text-purple border border-purple"
            : "badge bg-danger-subtle text-danger border border-danger";
        badge.textContent = isHttp ? "TRAP" : "DENIED";
        if (isHttp) {
            badge.style.backgroundColor = "rgba(192,132,252,0.15)";
            badge.style.borderColor = "#a855f7";
            badge.style.color = "#c084fc";
        }
        tdStatus.appendChild(badge);
        tr.appendChild(tdStatus);

        tbody.insertBefore(tr, tbody.firstChild);
        if (tbody.children.length > 50) tbody.removeChild(tbody.lastChild);
    }

    // ── 4. Alert Cards (textContent Anti-XSS) ───────────────────
    function prependAlertCard(al) {
        const panel = document.getElementById("alertsPanel");
        if (!panel) return;

        const sev = (al.severity || "MEDIUM").toUpperCase();
        const card = document.createElement("div");
        card.className = "p-2 mb-2 rounded small";
        card.style.cssText = "background:rgba(255,255,255,0.03);border:1px solid #334155";

        const header = document.createElement("div");
        header.className = "d-flex justify-content-between align-items-center mb-1";

        const left = document.createElement("div");
        left.className = "d-flex align-items-center gap-2";
        left.appendChild(severityBadge(sev));

        const ruleSpan = document.createElement("strong");
        ruleSpan.className = "text-label fs-8";
        ruleSpan.textContent = al.rule_name || al.rule || "RULE_TRIGGER";
        left.appendChild(ruleSpan);

        const timeSpan = document.createElement("span");
        timeSpan.className = "text-muted-soc fs-8";
        timeSpan.textContent = al.timestamp || new Date().toLocaleTimeString();

        header.appendChild(left);
        header.appendChild(timeSpan);

        const descP = document.createElement("p");
        descP.className = "mb-1 text-label small";
        descP.textContent = al.description;

        const footer = document.createElement("div");
        footer.className = "text-muted-soc fs-8";
        footer.textContent = `IP: ${al.ip}  |  ${al.blocked ? "🔒 Firewall Blocked" : "📋 Logged"}`;

        card.appendChild(header);
        card.appendChild(descP);
        card.appendChild(footer);
        panel.insertBefore(card, panel.firstChild);

        // Keep panel manageable
        while (panel.children.length > 30) panel.removeChild(panel.lastChild);
    }

    // ── 5. Update Top Usernames / Passwords tables ───────────────
    function buildTopTable(tableBodyId, items, keyField, valClass) {
        const tbody = document.getElementById(tableBodyId);
        if (!tbody) return;
        tbody.replaceChildren();
        (items || []).forEach((item, i) => {
            const tr = document.createElement("tr");

            const rankTd = document.createElement("td");
            rankTd.className = "text-muted-soc fs-8";
            rankTd.textContent = `#${i + 1}`;

            const valTd = document.createElement("td");
            valTd.className = `font-monospace ${valClass} text-truncate`;
            valTd.style.maxWidth = "160px";
            valTd.textContent = item[keyField] || "—";

            const countTd = document.createElement("td");
            const badge = document.createElement("span");
            badge.className = "badge bg-secondary-subtle text-label rounded-pill";
            badge.textContent = item.count;
            countTd.appendChild(badge);

            tr.appendChild(rankTd);
            tr.appendChild(valTd);
            tr.appendChild(countTd);
            tbody.appendChild(tr);
        });
    }

    // ── 6. Analytics UI update ───────────────────────────────────
    function updateAnalyticsUI(stats) {
        if (!stats) return;

        const threatElem = document.getElementById("statThreatLevel");
        if (threatElem && stats.threat_level) {
            threatElem.textContent = stats.threat_level;
            threatElem.className = `fw-bold mt-1 mb-0 threat-badge threat-${stats.threat_level.toLowerCase()}`;
        }

        const setNum = (id, val) => {
            const el = document.getElementById(id);
            if (el && val !== undefined) el.textContent = val;
        };
        setNum("statTotalAttacks", stats.total_attacks);
        setNum("statTotalAlerts",  stats.total_alerts);
        setNum("statTotalBlocked", stats.total_blocked);

        // Top tables
        buildTopTable("topUsernamesBody", stats.top_usernames, "username", "text-info");
        buildTopTable("topPasswordsBody", stats.top_passwords, "password", "text-warning");

        // Line chart update
        if (attackChart && stats.attacks_per_min && stats.attacks_per_min.length > 0) {
            attackChart.data.labels = stats.attacks_per_min.map(r => r.minute_bucket);
            attackChart.data.datasets[0].data = stats.attacks_per_min.map(r => r.count);
            attackChart.update("none");
        }
    }

    // ── 7. Blocked IPs list ──────────────────────────────────────
    function refreshBlockedIps() {
        fetch("/api/blocked")
            .then(r => r.json())
            .then(list => {
                const ul = document.getElementById("listBlockedIps");
                if (!ul) return;
                ul.replaceChildren();
                if (!list || list.length === 0) {
                    const li = document.createElement("li");
                    li.className = "list-group-item text-muted-soc small px-0";
                    li.textContent = "No active firewall blocks";
                    ul.appendChild(li);
                    return;
                }
                list.forEach(b => {
                    const li = document.createElement("li");
                    li.className = "list-group-item d-flex justify-content-between align-items-center px-0 py-1 small";

                    const sp = document.createElement("span");
                    sp.className = "font-monospace text-danger";
                    sp.textContent = `${b.ip}  (${String(b.reason).substring(0, 20)})`;

                    const btn = document.createElement("button");
                    btn.className = "btn btn-outline-secondary btn-xs py-0 px-2 fs-8";
                    btn.textContent = "Unblock";
                    btn.onclick = () => {
                        fetch(`/api/unblock/${encodeURIComponent(b.ip)}`, { method: "POST" })
                            .then(r => r.json())
                            .then(() => refreshBlockedIps());
                    };

                    li.appendChild(sp);
                    li.appendChild(btn);
                    ul.appendChild(li);
                });
            })
            .catch(console.error);
    }

    // ── 8. Initial page load ─────────────────────────────────────
    function initialLoad() {
        fetch("/api/attacks?limit=25")
            .then(r => r.json())
            .then(attacks => attacks.reverse().forEach(prependAttackRow));

        fetch("/api/alerts?limit=20")
            .then(r => r.json())
            .then(alerts => {
                alerts.reverse().forEach(prependAlertCard);
                updateBreakdownChart(alerts);
            });

        fetch("/api/stats")
            .then(r => r.json())
            .then(updateAnalyticsUI);

        refreshBlockedIps();
    }

    initialLoad();

    // ── 9. WebSocket events ──────────────────────────────────────
    const socket = io();
    socket.on("connect", () => console.log("[HoneyGuard] WebSocket connected."));

    socket.on("new_attack", payload => {
        if (payload.attack) {
            prependAttackRow(payload.attack);
            if (payload.attack.triggered_rules && payload.attack.triggered_rules.length > 0) {
                payload.attack.triggered_rules.forEach(prependAlertCard);
                refreshBlockedIps();
            }
        }
        if (payload.summary) updateAnalyticsUI(payload.summary);

        // Re-fetch alerts for breakdown chart update
        fetch("/api/alerts?limit=50")
            .then(r => r.json())
            .then(updateBreakdownChart);
    });

    socket.on("new_canary", payload => {
        if (payload.canary) {
            prependAlertCard({
                rule_name: "CANARY_BREACH",
                severity: "CRITICAL",
                description: payload.canary.description,
                ip: "127.0.0.1",
                timestamp: new Date().toLocaleTimeString()
            });
            // Non-blocking notification
            const notif = document.getElementById("canaryNotif");
            if (notif) {
                notif.style.display = "block";
                setTimeout(() => { notif.style.display = "none"; }, 8000);
            }
        }
        if (payload.summary) updateAnalyticsUI(payload.summary);
    });

    // ── 10. PDF Report button ────────────────────────────────────
    const btnReport = document.getElementById("btnGenerateReport");
    if (btnReport) {
        btnReport.addEventListener("click", () => {
            btnReport.disabled = true;
            btnReport.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-1"></i> Generating...';
            fetch("/api/generate_report", { method: "POST" })
                .then(r => r.json())
                .then(data => {
                    btnReport.disabled = false;
                    btnReport.innerHTML = '<i class="fa-solid fa-file-pdf me-1"></i> Generate PDF Report';
                    if (data.success && data.download_url) {
                        window.location.href = data.download_url;
                    } else {
                        alert("Report generation failed: " + (data.error || "Unknown error"));
                    }
                })
                .catch(() => {
                    btnReport.disabled = false;
                    btnReport.innerHTML = '<i class="fa-solid fa-file-pdf me-1"></i> Generate PDF Report';
                    alert("Network error generating report");
                });
        });
    }

    // ── 11. 1-Click Attack Simulator ─────────────────────────────
    const simBtns = document.querySelectorAll("[data-sim-type]");
    const simStatus = document.getElementById("simStatusBadge");
    const simLog = document.getElementById("simLog");

    function setSimRunning(running) {
        simBtns.forEach(b => { b.disabled = running; });
        if (simStatus) {
            simStatus.textContent = running ? "⚡ Running…" : "🟢 Ready";
            simStatus.className = running
                ? "badge bg-warning text-dark"
                : "badge bg-success";
        }
    }

    function appendSimLog(msg, cls = "text-label") {
        if (!simLog) return;
        const line = document.createElement("div");
        line.className = `small ${cls} font-monospace`;
        line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
        simLog.prepend(line);
        while (simLog.children.length > 15) simLog.removeChild(simLog.lastChild);
    }

    function pollSimStatus() {
        fetch("/api/simulate/status")
            .then(r => r.json())
            .then(d => {
                if (d.running) {
                    setTimeout(pollSimStatus, 800);
                } else {
                    setSimRunning(false);
                    appendSimLog("Simulation complete — check live feed ✔", "text-success");
                    // Refresh UI after simulation finishes
                    fetch("/api/stats").then(r => r.json()).then(updateAnalyticsUI);
                    refreshBlockedIps();
                }
            })
            .catch(() => setSimRunning(false));
    }

    simBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            const simType = btn.dataset.simType;
            setSimRunning(true);
            appendSimLog(`Starting simulation: ${simType.replace("_", " ").toUpperCase()}…`, "text-warning");

            fetch(`/api/simulate/${simType}`, { method: "POST" })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        appendSimLog(data.message, "text-info");
                        pollSimStatus();
                    } else {
                        setSimRunning(false);
                        appendSimLog("Error: " + (data.error || "Unknown"), "text-danger");
                    }
                })
                .catch(err => {
                    setSimRunning(false);
                    appendSimLog("Network error: " + err, "text-danger");
                });
        });
    });

});
