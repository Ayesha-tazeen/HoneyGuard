"""
HoneyGuard PDF Security Report Generator
Produces professional executive-level intrusion & threat intelligence reports
using ReportLab. Designed for college viva presentations and small business auditing.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import config
import db

def generate_pdf_report(output_filename: Optional[str] = None) -> str:
    """
    Generates a comprehensive PDF security summary report.
    Returns the absolute path to the generated PDF.
    """
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if not output_filename:
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"honeyguard_report_{timestamp_str}.pdf"

    pdf_path = config.REPORTS_DIR / output_filename

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#1e293b"),
        alignment=0
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b")
    )

    h2_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155")
    )

    elements = []

    # Title & Metadata
    elements.append(Paragraph("🛡️ HoneyGuard Intrusion Detection & Threat Report", title_style))
    elements.append(Paragraph(
        f"Generated on: {datetime.now().strftime('%A, %B %d, %Y at %I:%M %p')} | "
        f"Target Scope: SME / Clinic / College Lab Network Honeypot",
        subtitle_style
    ))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#3b82f6"), spaceAfter=14))

    # Analytics Data Fetch
    analytics = db.get_analytics_summary()
    threat_level = analytics.get("threat_level", "LOW")

    # Threat Level Color Mapping
    threat_color = colors.HexColor("#10b981")  # Green
    if threat_level == "MEDIUM":
        threat_color = colors.HexColor("#f59e0b")  # Amber
    elif threat_level == "HIGH":
        threat_color = colors.HexColor("#ef4444")  # Red

    # 1. Executive Summary Table
    elements.append(Paragraph("1. Executive Threat Summary", h2_style))
    
    summary_data = [
        [
            Paragraph("<b>Overall Threat Level</b>", body_style),
            Paragraph(f"<b><font color='{threat_color.hexval()}'>{threat_level}</font></b>", body_style),
            Paragraph("<b>Total Login Attacks Captured</b>", body_style),
            Paragraph(f"<b>{analytics['total_attacks']}</b>", body_style)
        ],
        [
            Paragraph("<b>High-Severity Alerts</b>", body_style),
            Paragraph(f"<b>{analytics['total_alerts']}</b>", body_style),
            Paragraph("<b>Firewall Blocked IPs</b>", body_style),
            Paragraph(f"<b>{analytics['total_blocked']} (Dry-Run: {config.DRY_RUN})</b>", body_style)
        ]
    ]

    t_summary = Table(summary_data, colWidths=[140, 130, 150, 120])
    t_summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(t_summary)
    elements.append(Spacer(1, 12))

    # 2. Top Targeted Credentials
    elements.append(Paragraph("2. Attacker Reconnaissance & Credential Profiling", h2_style))

    cred_data = [["Rank", "Target Username", "Attempts", "Most Used Password", "Attempts"]]
    top_u = analytics.get("top_usernames", [])
    top_p = analytics.get("top_passwords", [])

    for i in range(max(len(top_u), len(top_p), 1)):
        u_name = top_u[i]["username"] if i < len(top_u) else "—"
        u_cnt = str(top_u[i]["count"]) if i < len(top_u) else "—"
        p_name = top_p[i]["password"] if i < len(top_p) else "—"
        p_cnt = str(top_p[i]["count"]) if i < len(top_p) else "—"
        cred_data.append([f"#{i+1}", u_name, u_cnt, p_name, p_cnt])

    t_cred = Table(cred_data, colWidths=[40, 150, 80, 190, 80])
    t_cred.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(t_cred)
    elements.append(Spacer(1, 12))

    # 3. Recent Attack Logs
    elements.append(Paragraph("3. Honeypot Activity Log (Last 10 Events)", h2_style))
    attacks = db.get_recent_attacks(limit=10)
    
    log_data = [["Timestamp (UTC)", "Attacker IP", "Location", "User Tried", "Password Tried"]]
    if attacks:
        for att in attacks:
            log_data.append([
                att["timestamp"],
                att["ip"],
                f"{att['city']}, {att['country']}"[:22],
                att["username"][:15],
                att["password"][:18]
            ])
    else:
        log_data.append(["No intrusion events recorded yet", "—", "—", "—", "—"])

    t_log = Table(log_data, colWidths=[100, 90, 140, 100, 110])
    t_log.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    elements.append(t_log)
    elements.append(Spacer(1, 14))

    # 4. Security Recommendations
    elements.append(Paragraph("4. Recommended Security Measures", h2_style))
    recommendations = [
        "1. <b>Change Default SSH Port:</b> Shift production SSH away from standard port 22 to reduce automated bot sweeps by over 90%.",
        "2. <b>Disable Password Authentication:</b> Enforce Ed25519 or RSA-4096 Public Key authentication and disable password logins in sshd_config.",
        "3. <b>Enforce Fail2ban / HoneyGuard Auto-Block:</b> Ensure auto-blocking firewall rules are activated in production mode (DRY_RUN=False).",
        "4. <b>Maintain Honeytokens (Canary Files):</b> Place decoy files (e.g. passwords.xlsx) on shared drives to instantly alert on insider or lateral movement threats."
    ]
    for rec in recommendations:
        elements.append(Paragraph(rec, body_style))
        elements.append(Spacer(1, 3))

    doc.build(elements)
    return str(pdf_path)
