"""Report generation service — PDF, JSON, CSV from actual scan data."""
from __future__ import annotations
import csv
import json
import os
import uuid
from datetime import datetime
from pathlib import Path


class ReportService:

    @staticmethod
    def generate(scan_id: int, generated_by_id: int, report_type: str) -> object:
        """
        Generate a security report for a completed scan.
        Returns SecurityReport ORM object.
        """
        from app import db
        from app.models.scan import Scan
        from app.models.vulnerability import Vulnerability
        from app.models.security_policy import SecurityReport
        from flask import current_app

        scan = db.session.get(Scan, scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        reports_dir_cfg = current_app.config.get("REPORTS_DIR", "reports")
        # Always resolve to absolute path
        if not os.path.isabs(reports_dir_cfg):
            reports_dir = Path(current_app.root_path).parent / reports_dir_cfg
        else:
            reports_dir = Path(reports_dir_cfg)
        reports_dir.mkdir(parents=True, exist_ok=True)

        report_uuid = str(uuid.uuid4())
        filename = f"secureflow_report_{scan_id}_{report_uuid[:8]}.{report_type}"
        file_path = str(reports_dir / filename)

        vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()
        scan_data = ReportService._build_scan_data(scan, vulns)

        if report_type == "pdf":
            ReportService._generate_pdf(scan_data, file_path)
        elif report_type == "json":
            ReportService._generate_json(scan_data, file_path)
        elif report_type == "csv":
            ReportService._generate_csv(scan_data, vulns, file_path)
        else:
            raise ValueError(f"Unsupported report type: {report_type}")

        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

        report = SecurityReport(
            report_uuid=report_uuid,
            scan_id=scan_id,
            repository_id=scan.repository_id,
            generated_by_id=generated_by_id,
            report_type=report_type,
            file_path=file_path,
            file_size_bytes=file_size,
        )
        db.session.add(report)
        db.session.commit()
        return report

    @staticmethod
    def _build_scan_data(scan, vulns) -> dict:
        return {
            "report_title": "SecureFlow Security Report",
            "generated_at": datetime.utcnow().isoformat(),
            "scan_id": scan.id,
            "scan_uuid": scan.scan_uuid,
            "repository": scan.repository.name if scan.repository else "Unknown",
            "repository_url": scan.repository.url if scan.repository else "",
            "branch": scan.branch or "main",
            "trigger_type": scan.trigger_type,
            "scan_status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_seconds": scan.duration_seconds,
            "security_score": scan.security_score,
            "gate_decision": scan.gate_decision,
            "total_vulnerabilities": scan.total_vulnerabilities,
            "critical_count": scan.critical_count,
            "high_count": scan.high_count,
            "medium_count": scan.medium_count,
            "low_count": scan.low_count,
            "secrets_count": scan.secrets_count,
            "vulnerabilities": [v.to_dict() for v in vulns],
        }

    @staticmethod
    def _generate_pdf(scan_data: dict, file_path: str) -> None:
        """Generate professional PDF report using ReportLab with proper word-wrap."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                             Table, TableStyle, HRFlowable, KeepTogether)
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

            PAGE_W, PAGE_H = A4
            MARGIN = 1.8 * cm
            CONTENT_W = PAGE_W - 2 * MARGIN

            doc = SimpleDocTemplate(
                file_path, pagesize=A4,
                leftMargin=MARGIN, rightMargin=MARGIN,
                topMargin=MARGIN, bottomMargin=MARGIN
            )
            styles = getSampleStyleSheet()

            # ── Custom styles ──────────────────────────────────────────────────
            heading_style = ParagraphStyle(
                "SFHeading", parent=styles["Title"],
                textColor=colors.HexColor("#0d1117"),
                fontSize=22, spaceAfter=4, fontName="Helvetica-Bold"
            )
            sub_style = ParagraphStyle(
                "SFSub", parent=styles["Normal"],
                textColor=colors.HexColor("#58a6ff"),
                fontSize=11, spaceAfter=2
            )
            section_style = ParagraphStyle(
                "SFSection", parent=styles["Heading2"],
                textColor=colors.HexColor("#0d1117"),
                fontSize=13, spaceBefore=12, spaceAfter=6,
                fontName="Helvetica-Bold"
            )
            cell_style = ParagraphStyle(
                "Cell", parent=styles["Normal"],
                fontSize=8, leading=11, wordWrap="CJK"
            )
            cell_bold = ParagraphStyle(
                "CellBold", parent=cell_style,
                fontName="Helvetica-Bold"
            )
            footer_style = ParagraphStyle(
                "Footer", parent=styles["Normal"],
                fontSize=8, textColor=colors.gray, alignment=TA_CENTER
            )

            # Severity hex colours (plain strings — no HexColor objects needed here)
            SEV_HEX = {
                "CRITICAL": "f85149",
                "HIGH":     "f0883e",
                "MEDIUM":   "d29922",
                "LOW":      "58a6ff",
                "INFO":     "8b949e",
            }

            story = []

            # ── Header ─────────────────────────────────────────────────────────
            story.append(Paragraph("SecureFlow Security Report", heading_style))
            story.append(Paragraph("Detect Early. Secure Always. Deploy Confidently.", sub_style))
            story.append(HRFlowable(width="100%", thickness=2,
                                     color=colors.HexColor("#58a6ff"), spaceAfter=8))

            # ── Scan Summary Table ─────────────────────────────────────────────
            story.append(Paragraph("Scan Summary", section_style))

            score = scan_data.get("security_score", "N/A")
            gate  = str(scan_data.get("gate_decision", "N/A")).upper()
            gate_color = colors.HexColor("#3fb950") if gate == "PASSED" else colors.HexColor("#f85149")

            def mk(text, bold=False):
                s = cell_bold if bold else cell_style
                return Paragraph(str(text), s)

            summary_rows = [
                [mk("Field", True),         mk("Value", True)],
                [mk("Repository"),          mk(scan_data.get("repository", ""))],
                [mk("Repository URL"),      mk(scan_data.get("repository_url", ""))],
                [mk("Branch"),              mk(scan_data.get("branch", "main"))],
                [mk("Scan ID"),             mk(str(scan_data.get("scan_id", "")))],
                [mk("Status"),              mk(scan_data.get("scan_status", "").upper())],
                [mk("Started At"),          mk(str(scan_data.get("started_at", ""))[:19] if scan_data.get("started_at") else "—")],
                [mk("Completed At"),        mk(str(scan_data.get("completed_at", ""))[:19] if scan_data.get("completed_at") else "—")],
                [mk("Generated At"),        mk(str(scan_data.get("generated_at", ""))[:19])],
                [mk("Security Score"),      mk(f"{score}/100")],
                [mk("Gate Decision"),       mk(gate)],
            ]

            st = Table(summary_rows, colWidths=[5*cm, CONTENT_W - 5*cm])
            st.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
                ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f0f6ff")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.HexColor("#f6f8fa"), colors.white]),
                ("GRID",    (0, 0), (-1, -1), 0.4, colors.HexColor("#30363d")),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN",  (0, 0), (-1, -1), "TOP"),
                # Gate decision row colour
                ("TEXTCOLOR", (1, 10), (1, 10), gate_color),
                ("FONTNAME",  (1, 10), (1, 10), "Helvetica-Bold"),
            ]))
            story.append(st)
            story.append(Spacer(1, 0.5*cm))

            # ── Vulnerability Counts ───────────────────────────────────────────
            story.append(Paragraph("Vulnerability Summary", section_style))
            count_data = [
                [mk("Severity", True), mk("Count", True), mk("Risk Weight", True)],
                [mk("Critical"), mk(str(scan_data.get("critical_count", 0))),
                 mk(f"−{min(scan_data.get('critical_count',0)*20, 60)} pts (max −60)")],
                [mk("High"),     mk(str(scan_data.get("high_count", 0))),
                 mk(f"−{min(scan_data.get('high_count',0)*10, 30)} pts (max −30)")],
                [mk("Medium"),   mk(str(scan_data.get("medium_count", 0))),
                 mk(f"−{min(scan_data.get('medium_count',0)*3, 15)} pts (max −15)")],
                [mk("Low"),      mk(str(scan_data.get("low_count", 0))),
                 mk(f"−{min(scan_data.get('low_count',0)*1, 5)} pts (max −5)")],
                [mk("Secrets"),  mk(str(scan_data.get("secrets_count", 0))),
                 mk(f"−{min(scan_data.get('secrets_count',0)*25, 50)} pts (max −50)")],
                [mk("TOTAL", True), mk(str(scan_data.get("total_vulnerabilities", 0)), True),
                 mk(f"Final Score: {score}/100", True)],
            ]
            col3 = CONTENT_W / 3
            ct = Table(count_data, colWidths=[col3, col3, col3])
            ct.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
                ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                ("GRID",    (0, 0), (-1, -1), 0.4, colors.HexColor("#30363d")),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN",  (0, 0), (-1, -1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -2),
                 [colors.HexColor("#f6f8fa"), colors.white]),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#eaf4ff")),
                ("FONTNAME",   (0, -1), (-1, -1), "Helvetica-Bold"),
                # Colour severity label cells
                ("TEXTCOLOR", (0, 1), (0, 1), colors.HexColor("#f85149")),  # critical
                ("TEXTCOLOR", (0, 2), (0, 2), colors.HexColor("#f0883e")),  # high
                ("TEXTCOLOR", (0, 3), (0, 3), colors.HexColor("#d29922")),  # medium
                ("TEXTCOLOR", (0, 4), (0, 4), colors.HexColor("#58a6ff")),  # low
            ]))
            story.append(ct)
            story.append(Spacer(1, 0.5*cm))

            # ── Vulnerability Findings Table ───────────────────────────────────
            story.append(Paragraph("Vulnerability Findings", section_style))

            vulns = scan_data.get("vulnerabilities", [])
            if vulns:
                # Column widths: Sev | Title | CVE/Package | Scanner | Status
                cws = [1.8*cm, 7.5*cm, 3.5*cm, 2.0*cm, 1.8*cm]
                hdr = [mk("Severity", True), mk("Title / Description", True),
                       mk("CVE / Package", True), mk("Scanner", True), mk("Status", True)]
                vuln_rows = [hdr]

                for v in vulns[:60]:  # cap at 60 rows
                    sev = str(v.get("severity", "")).upper()
                    sev_hex = SEV_HEX.get(sev, "333333")
                    sev_para = Paragraph(
                        f'<font color="#{sev_hex}"><b>{sev}</b></font>',
                        cell_style
                    )
                    # Title — truncate gracefully
                    title = str(v.get("title", ""))[:120]
                    pkg   = v.get("package_name", "")
                    ver   = v.get("installed_version", "")
                    fix   = v.get("fixed_version", "")
                    cve   = v.get("cve_id", "")
                    pkg_line = cve or (f"{pkg} {ver}" if pkg else "")
                    if fix:
                        pkg_line += f"\nFix: {fix}"

                    vuln_rows.append([
                        sev_para,
                        mk(title),
                        mk(pkg_line),
                        mk(str(v.get("scanner", ""))),
                        mk(str(v.get("status", "open"))),
                    ])

                vt = Table(vuln_rows, colWidths=cws, repeatRows=1)
                vt.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
                    ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                    ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID",    (0, 0), (-1, -1), 0.3, colors.HexColor("#d0d7de")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN",  (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                     [colors.HexColor("#f6f8fa"), colors.white]),
                ]))
                story.append(vt)

                if len(vulns) > 60:
                    story.append(Spacer(1, 0.3*cm))
                    story.append(Paragraph(
                        f"Note: Showing first 60 of {len(vulns)} findings. "
                        "Download the JSON or CSV report for the complete list.",
                        ParagraphStyle("note", parent=cell_style,
                                       textColor=colors.gray, fontSize=8)
                    ))
            else:
                story.append(Paragraph(
                    "✅  No vulnerabilities detected in this scan.",
                    ParagraphStyle("ok", parent=styles["Normal"],
                                   textColor=colors.HexColor("#3fb950"), fontSize=11)
                ))

            story.append(Spacer(1, 0.6*cm))
            story.append(HRFlowable(width="100%", thickness=0.5,
                                     color=colors.HexColor("#30363d")))
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph(
                "Generated by SecureFlow DevSecOps Platform  |  Confidential  |  "
                f"Scan #{scan_data.get('scan_id', '')}",
                footer_style
            ))

            doc.build(story)

        except ImportError:
            # Fallback: plain text
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("SecureFlow Security Report\n" + "=" * 50 + "\n")
                for key, val in scan_data.items():
                    if key != "vulnerabilities":
                        f.write(f"{key}: {val}\n")
                f.write("\nVulnerability Findings:\n" + "-" * 40 + "\n")
                for v in scan_data.get("vulnerabilities", []):
                    f.write(f"[{v.get('severity','?').upper()}] {v.get('title','')} "
                            f"({v.get('scanner','')}) - {v.get('status','open')}\n")


    @staticmethod
    def _generate_json(scan_data: dict, file_path: str) -> None:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(scan_data, f, indent=2, default=str)

    @staticmethod
    def _generate_csv(scan_data: dict, vulns, file_path: str) -> None:
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "ID", "Scanner", "Severity", "Title", "CVE ID",
                "Package", "Installed Version", "Fixed Version",
                "File", "Line", "Status", "Remediation",
            ])
            for v in vulns:
                writer.writerow([
                    v.id, v.scanner, v.severity, v.title,
                    v.cve_id or "", v.package_name or "",
                    v.installed_version or "", v.fixed_version or "",
                    v.file_path or "", v.line_number or "",
                    v.status, (v.remediation or "")[:200],
                ])
