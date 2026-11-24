/**
 * HoneyGuard Live SOC Dashboard Client
 * Real-time event handling via WebSockets (Socket.IO).
 * 
 * CRITICAL VIVA SECURITY SAFEGUARD:
 * All attacker-supplied strings (usernames, passwords, user agents, IPs)
 * are injected using `textContent` and DOM nodes to guarantee IMMUNITY against
 * Cross-Site Scripting (XSS) attacks.
 */

document.addEventListener("DOMContentLoaded", () => {
    // 1. Initialize Map (Leaflet.js)
    const map = L.map('attackMap').setView([20.0, 10.0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; OpenStreetMap contributors',
        maxZoom: 18
    }).addTo(map);

    const markerGroup = L.layerGroup().addTo(map);

    function addMapMarker(lat, lon, title, text) {
        if (!lat || !lon || (lat === 0 && lon === 0)) return;
        const marker = L.circleMarker([lat, lon], {
            radius: 7,
            fillColor: '#ef4444',
            color: '#fff',
            weight: 1.5,
            opacity: 1,
            fillOpacity: 0.8
        });
        marker.bindPopup(`<b>${escapeHtml(title)}</b><br>${escapeHtml(text)}`);
        markerGroup.addLayer(marker);
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // 2. Initialize Chart (Chart.js)
    const ctx = document.getElementById('attackChart').getContext('2d');
    const attackChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Attempts / Min',
                data: [],
                borderColor: '#10b981',
                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                borderWidth: 2,
                tension: 0.3,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: '#1f2937' },
                    ticks: { color: '#9ca3af', precision: 0 }
                },
                x: {
                    grid: { color: '#1f2937' },
                    ticks: { color: '#9ca3af' }
                }
            },
            plugins: {
                legend: { labels: { color: '#e5e7eb' } }
            }
        }
    });

    // Helper: Safely create table cells with textContent (Anti-XSS)
    function createSafeCell(text, className = '') {
        const td = document.createElement('td');
        td.textContent = text;
        if (className) td.className = className;
        return td;
    }

    // Prepend attack entry safely
    function prependAttackRow(att) {
        const tbody = document.getElementById('attackFeedBody');
        const tr = document.createElement('tr');

        const timeStr = att.timestamp || new Date().toISOString().replace('T', ' ').substring(11, 19);
        tr.appendChild(createSafeCell(timeStr, 'text-secondary'));
        tr.appendChild(createSafeCell(att.ip, 'fw-semibold text-info'));
        tr.appendChild(createSafeCell(`${att.city || 'Unknown'}, ${att.country || 'Unknown'}`));
        
        // Attacker payload usernames/passwords rendered via textContent ONLY
        tr.appendChild(createSafeCell(att.username || '—', 'text-warning font-monospace'));
        tr.appendChild(createSafeCell(att.password || '—', 'text-light font-monospace'));

        // Status badge
        const tdStatus = document.createElement('td');
        const badge = document.createElement('span');
        badge.className = 'badge bg-danger-subtle text-danger border border-danger';
        badge.textContent = 'DENIED';
        tdStatus.appendChild(badge);
        tr.appendChild(tdStatus);

        tbody.insertBefore(tr, tbody.firstChild);

        // Keep table to at most 35 rows
        if (tbody.children.length > 35) {
            tbody.removeChild(tbody.lastChild);
        }

        // Add to Leaflet map
        if (att.latitude && att.longitude) {
            addMapMarker(att.latitude, att.longitude, att.ip, `${att.city}, ${att.country} (User: ${att.username})`);
        }
    }

    // Safely add alert card (Anti-XSS)
    function prependAlertCard(al) {
        const panel = document.getElementById('alertsPanel');
        const card = document.createElement('div');
        
        const sev = (al.severity || 'HIGH').toUpperCase();
        let borderClass = 'border-warning text-warning';
        if (sev === 'CRITICAL' || sev === 'HIGH') borderClass = 'border-danger text-danger';

        card.className = `p-2 mb-2 rounded bg-dark border ${borderClass} small`;

        const titleDiv = document.createElement('div');
        titleDiv.className = 'd-flex justify-content-between align-items-center mb-1';

        const titleText = document.createElement('strong');
        titleText.textContent = `[${sev}] ${al.rule_name || al.rule || 'RULE_TRIGGER'}`;

        const timeSpan = document.createElement('span');
        timeSpan.className = 'text-secondary fs-8';
        timeSpan.textContent = al.timestamp || new Date().toLocaleTimeString();

        titleDiv.appendChild(titleText);
        titleDiv.appendChild(timeSpan);

        const descP = document.createElement('p');
        descP.className = 'mb-1 text-light';
        descP.textContent = al.description;

        const footerDiv = document.createElement('div');
        footerDiv.className = 'text-secondary fs-8';
        footerDiv.textContent = `Target IP: ${al.ip} | Action: ${al.blocked ? 'Firewall Blocked' : 'Logged'}`;

        card.appendChild(titleDiv);
        card.appendChild(descP);
        card.appendChild(footerDiv);

        panel.insertBefore(card, panel.firstChild);
    }

    // Refresh Analytics UI
    function updateAnalyticsUI(stats) {
        if (!stats) return;

        // Threat level badge
        const threatElem = document.getElementById('statThreatLevel');
        if (threatElem && stats.threat_level) {
            threatElem.textContent = stats.threat_level;
            threatElem.className = `fw-bold mt-1 mb-0 threat-badge threat-${stats.threat_level.toLowerCase()}`;
        }

        if (stats.total_attacks !== undefined) {
            document.getElementById('statTotalAttacks').textContent = stats.total_attacks;
        }
        if (stats.total_alerts !== undefined) {
            document.getElementById('statTotalAlerts').textContent = stats.total_alerts;
        }
        if (stats.total_blocked !== undefined) {
            document.getElementById('statTotalBlocked').textContent = stats.total_blocked;
        }

        // Top Passwords (Safe DOM building)
        const passList = document.getElementById('listTopPasswords');
        passList.replaceChildren();
        (stats.top_passwords || []).forEach(item => {
            const li = document.createElement('li');
            li.className = 'list-group-item bg-transparent d-flex justify-content-between align-items-center px-0 py-1 text-light small';
            const spanKey = document.createElement('span');
            spanKey.className = 'font-monospace text-warning text-truncate';
            spanKey.style.maxWidth = '180px';
            spanKey.textContent = item.password;
            const badge = document.createElement('span');
            badge.className = 'badge bg-secondary-subtle text-light rounded-pill';
            badge.textContent = item.count;
            li.appendChild(spanKey);
            li.appendChild(badge);
            passList.appendChild(li);
        });

        // Top Usernames (Safe DOM building)
        const userList = document.getElementById('listTopUsernames');
        userList.replaceChildren();
        (stats.top_usernames || []).forEach(item => {
            const li = document.createElement('li');
            li.className = 'list-group-item bg-transparent d-flex justify-content-between align-items-center px-0 py-1 text-light small';
            const spanUser = document.createElement('span');
            spanUser.className = 'font-monospace text-info text-truncate';
            spanUser.style.maxWidth = '180px';
            spanUser.textContent = item.username;
            const badge = document.createElement('span');
            badge.className = 'badge bg-secondary-subtle text-light rounded-pill';
            badge.textContent = item.count;
            li.appendChild(spanUser);
            li.appendChild(badge);
            userList.appendChild(li);
        });

        // Chart updates
        if (stats.attacks_per_min && stats.attacks_per_min.length > 0) {
            attackChart.data.labels = stats.attacks_per_min.map(row => row.minute_bucket);
            attackChart.data.datasets[0].data = stats.attacks_per_min.map(row => row.count);
            attackChart.update();
        }
    }

    // Refresh Blocked IPs List
    function refreshBlockedIps() {
        fetch('/api/blocked')
            .then(res => res.json())
            .then(list => {
                const ul = document.getElementById('listBlockedIps');
                ul.replaceChildren();
                if (!list || list.length === 0) {
                    const li = document.createElement('li');
                    li.className = 'list-group-item bg-transparent text-secondary small px-0';
                    li.textContent = 'No active firewall blocks';
                    ul.appendChild(li);
                    return;
                }
                list.forEach(b => {
                    const li = document.createElement('li');
                    li.className = 'list-group-item bg-transparent d-flex justify-content-between align-items-center px-0 py-1 text-light small';
                    
                    const spanIp = document.createElement('span');
                    spanIp.className = 'font-monospace text-danger';
                    spanIp.textContent = `${b.ip} (${b.reason.substring(0, 16)})`;

                    const btnUnblock = document.createElement('button');
                    btnUnblock.className = 'btn btn-outline-secondary btn-xs py-0 px-2 fs-8';
                    btnUnblock.textContent = 'Unblock';
                    btnUnblock.onclick = () => {
                        fetch(`/api/unblock/${encodeURIComponent(b.ip)}`, { method: 'POST' })
                            .then(res => res.json())
                            .then(res => {
                                refreshBlockedIps();
                            });
                    };

                    li.appendChild(spanIp);
                    li.appendChild(btnUnblock);
                    ul.appendChild(li);
                });
            })
            .catch(console.error);
    }

    // Initial Data Fetch
    function initialLoad() {
        // Fetch recent attacks
        fetch('/api/attacks?limit=25')
            .then(res => res.json())
            .then(attacks => {
                attacks.reverse().forEach(att => prependAttackRow(att));
            });

        // Fetch recent alerts
        fetch('/api/alerts?limit=15')
            .then(res => res.json())
            .then(alerts => {
                alerts.reverse().forEach(al => prependAlertCard(al));
            });

        // Fetch stats
        fetch('/api/stats')
            .then(res => res.json())
            .then(stats => updateAnalyticsUI(stats));

        refreshBlockedIps();
    }

    initialLoad();

    // 3. Connect to SocketIO for Real-Time Updates
    const socket = io();

    socket.on('connect', () => {
        console.log('Connected to HoneyGuard SOC WebSockets');
    });

    socket.on('new_attack', (payload) => {
        if (payload.attack) {
            prependAttackRow(payload.attack);
            // If rules triggered
            if (payload.attack.triggered_rules && payload.attack.triggered_rules.length > 0) {
                payload.attack.triggered_rules.forEach(rule => prependAlertCard(rule));
                refreshBlockedIps();
            }
        }
        if (payload.summary) {
            updateAnalyticsUI(payload.summary);
        }
    });

    socket.on('new_canary', (payload) => {
        if (payload.canary) {
            prependAlertCard({
                rule_name: 'CANARY_BREACH',
                severity: 'CRITICAL',
                description: payload.canary.description,
                ip: '127.0.0.1',
                timestamp: new Date().toLocaleTimeString()
            });
            alert('🚨 CRITICAL ALERT: Canary decoy file (passwords.xlsx) was accessed or modified!');
        }
        if (payload.summary) {
            updateAnalyticsUI(payload.summary);
        }
    });

    // 4. Generate PDF Report Button
    const btnReport = document.getElementById('btnGenerateReport');
    if (btnReport) {
        btnReport.addEventListener('click', () => {
            btnReport.disabled = true;
            btnReport.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-1"></i> Generating...';

            fetch('/api/generate_report', { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    btnReport.disabled = false;
                    btnReport.innerHTML = '<i class="fa-solid fa-file-pdf me-1"></i> Generate PDF Report';
                    if (data.success && data.download_url) {
                        window.location.href = data.download_url;
                    } else {
                        alert('Report generation failed: ' + (data.error || 'Unknown error'));
                    }
                })
                .catch(err => {
                    btnReport.disabled = false;
                    btnReport.innerHTML = '<i class="fa-solid fa-file-pdf me-1"></i> Generate PDF Report';
                    alert('Network error generating report');
                });
        });
    }
});
