"""
Report Generator — JSON, HTML, and Markdown security reports.

The :class:`ReportGenerator` class consumes lists of :class:`Finding`
objects (from :class:`SecurityScanner` or :class:`RedTeam`) and
produces professional reports in multiple formats.

Usage::

    from ai_security import ReportGenerator, SecurityScanner

    scanner = SecurityScanner(target="https://api.example.com/v1/chat")
    findings = scanner.run_scan(categories=["LLM01"])

    reporter = ReportGenerator()
    reporter.to_json(findings, "report.json")
    reporter.to_html(findings, "report.html")
    reporter.to_markdown(findings, "report.md")
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from .scanner import Finding, Severity, Vulnerability

# ---------------------------------------------------------------------------
# Format enum
# ---------------------------------------------------------------------------


class ReportFormat(str, Enum):
    """Supported report output formats."""

    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"


# ---------------------------------------------------------------------------
# Severity colour helpers
# ---------------------------------------------------------------------------

_SEVERITY_COLORS: Dict[str, str] = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#28a745",
    "INFO": "#17a2b8",
}

_SEVERITY_BADGE: Dict[str, str] = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "🟢 LOW",
    "INFO": "ℹ️ INFO",
}

# ---------------------------------------------------------------------------
# Remediation knowledge base
# ---------------------------------------------------------------------------

_REMEDIATION_KB: Dict[str, str] = {
    "LLM01": (
        "Implement structural separation between system prompts and user input. "
        "Treat all external content as untrusted. Deploy input sanitization and "
        "output validation. Use parameterized prompt templates. Consider a "
        "secondary LLM guard layer to validate response safety."
    ),
    "LLM02": (
        "Add output encoding and escaping for all LLM-generated content. "
        "Implement Content-Security-Policy headers. Never directly insert "
        "LLM output into HTML, SQL, or shell without sanitization. Validate "
        "all generated code before execution."
    ),
    "LLM03": (
        "Verify training data provenance. Implement data integrity checks. "
        "Use differential privacy during training. Apply robust fine-tuning "
        "techniques (RLHF, DPO). Regular model behavioural audits."
    ),
    "LLM04": (
        "Implement strict input length limits and token consumption tracking. "
        "Deploy rate limiting and abuse detection. Use sliding window context "
        "management. Set generation timeouts."
    ),
    "LLM05": (
        "Verify model provenance with signatures and checksums. Use trusted "
        "model registries only. Implement SBOM validation. Deploy supply-chain "
        "security monitoring."
    ),
    "LLM06": (
        "Isolate credentials from model access. Implement secret scanning in "
        "all outputs. Use credential managers and rotation. Deploy response "
        "filtering with allowlists."
    ),
    "LLM07": (
        "Implement parameter validation and type checking for all tool calls. "
        "Use parameterized queries. Sandbox tool execution environments. "
        "Apply principle of least privilege. Require human approval for "
        "high-risk tool calls."
    ),
    "LLM08": (
        "Define and enforce strict agent permission boundaries. Implement "
        "human approval for high-risk actions. Deploy agent activity "
        "monitoring and auditing. Use RBAC for agent operations."
    ),
    "LLM09": (
        "Implement fact-checking and source verification. Add confidence "
        "indicators to responses. Require source attribution for factual "
        "claims. Use RAG with verified knowledge bases."
    ),
    "LLM10": (
        "Implement API rate limiting and query pattern monitoring. Add model "
        "watermarks and fingerprinting. Limit output detail. Deploy detection "
        "for distillation attacks."
    ),
}

# ---------------------------------------------------------------------------
# ReportGenerator
# ---------------------------------------------------------------------------


class ReportGenerator:
    """Multi-format security report generator.

    Accepts a list of :class:`Finding` objects and produces reports in
    JSON, HTML, or Markdown format.

    Args:
        title: Report title (default: ``"AI Security Assessment Report"``).
        include_remediation: Whether to add category-level remediation
            text (default: ``True``).
    """

    def __init__(
        self,
        title: str = "AI Security Assessment Report",
        include_remediation: bool = True,
    ) -> None:
        self._title = title
        self._include_remediation = include_remediation

    # ------------------------------------------------------------------
    # Public: generate
    # ------------------------------------------------------------------

    def generate_json(self, findings: List[Finding]) -> str:
        """Generate a machine-readable JSON report.

        Args:
            findings: List of :class:`Finding` objects.

        Returns:
            JSON string with full report structure.
        """
        report = self._build_report_dict(findings)
        return json.dumps(report, indent=2, default=str)

    def generate_html(self, findings: List[Finding]) -> str:
        """Generate a human-readable HTML report with severity colours.

        Args:
            findings: List of :class:`Finding` objects.

        Returns:
            Complete HTML document.
        """
        return self._build_html(findings)

    def generate_markdown(self, findings: List[Finding]) -> str:
        """Generate a Markdown report suitable for GitHub issues.

        Args:
            findings: List of :class:`Finding` objects.

        Returns:
            Markdown string.
        """
        return self._build_markdown(findings)

    # ------------------------------------------------------------------
    # Public: save to file
    # ------------------------------------------------------------------

    def save(
        self,
        findings: List[Finding],
        format: ReportFormat | str = ReportFormat.JSON,
        output_path: str | Path = "report",
    ) -> str:
        """Generate report and write to file, inferring extension from format.

        Args:
            findings: List of :class:`Finding` objects.
            format: Output format (enum or string).
            output_path: File path (if it lacks an extension, the proper
                one is appended).

        Returns:
            Absolute path to the written file.
        """
        fmt = self._resolve_format(format)
        ext = {"json": ".json", "html": ".html", "markdown": ".md"}[fmt.value]
        p = Path(output_path)
        if p.suffix == "":
            p = p.with_suffix(ext)
        if p.suffix.lower() != ext:
            p = p.with_suffix(ext)

        content = self._generate(findings, fmt)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return str(p.resolve())

    # ------------------------------------------------------------------
    # Convenience wrappers
    # ------------------------------------------------------------------

    def to_json(
        self, findings: List[Finding], output_path: str | Path = "report.json"
    ) -> str:
        """Generate and save a JSON report.  Returns file path."""
        return self.save(findings, ReportFormat.JSON, output_path)

    def to_html(
        self, findings: List[Finding], output_path: str | Path = "report.html"
    ) -> str:
        """Generate and save an HTML report.  Returns file path."""
        return self.save(findings, ReportFormat.HTML, output_path)

    def to_markdown(
        self,
        findings: List[Finding],
        output_path: str | Path = "report.md",
    ) -> str:
        """Generate and save a Markdown report.  Returns file path."""
        return self.save(findings, ReportFormat.MARKDOWN, output_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_format(fmt: ReportFormat | str) -> ReportFormat:
        """Coerce a format value to a :class:`ReportFormat` enum."""
        if isinstance(fmt, ReportFormat):
            return fmt
        try:
            return ReportFormat(fmt.lower())
        except ValueError:
            raise ValueError(
                f"Unknown report format: {fmt!r}. "
                f"Expected one of: {', '.join(f.value for f in ReportFormat)}"
            )

    def _generate(self, findings: List[Finding], fmt: ReportFormat) -> str:
        """Dispatch to the appropriate generator."""
        if fmt == ReportFormat.JSON:
            return self.generate_json(findings)
        if fmt == ReportFormat.HTML:
            return self.generate_html(findings)
        if fmt == ReportFormat.MARKDOWN:
            return self.generate_markdown(findings)
        raise ValueError(f"Unsupported format: {fmt}")

    def _build_report_dict(self, findings: List[Finding]) -> Dict[str, Any]:
        """Build the canonical report dictionary."""
        summary = self._compute_summary(findings)
        report: Dict[str, Any] = {
            "title": self._title,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "framework_version": "2.0.0",
            "summary": summary,
            "findings": [f.to_dict() for f in findings],
        }
        if self._include_remediation:
            report["remediation"] = self._build_remediation(findings)
        return report

    @staticmethod
    def _compute_summary(findings: List[Finding]) -> Dict[str, Any]:
        """Compute aggregate statistics over findings."""
        total = len(findings)
        vulnerable = sum(1 for f in findings if f.is_vulnerable)
        cvss_scores = [f.cvss_score for f in findings if f.cvss_score > 0]

        by_sev: Dict[str, int] = {}
        for f in findings:
            label = f.vulnerability.severity.value
            by_sev[label] = by_sev.get(label, 0) + 1

        by_owasp: Dict[str, int] = {}
        for f in findings:
            cat = f.vulnerability.owasp_category or "unknown"
            vuln_count = 1 if f.is_vulnerable else 0
            if cat not in by_owasp:
                by_owasp[cat] = vuln_count
            else:
                by_owasp[cat] += vuln_count

        return {
            "total_findings": total,
            "total_vulnerable": vulnerable,
            "total_passed": total - vulnerable,
            "by_severity": by_sev,
            "by_owasp_category": by_owasp,
            "average_cvss": round(sum(cvss_scores) / len(cvss_scores), 2)
            if cvss_scores
            else 0.0,
            "worst_severity": max(
                (f.vulnerability.severity.value for f in findings),
                key=lambda s: Severity(s).sort_key,
                default="NONE",
            ),
        }

    @staticmethod
    def _build_remediation(findings: List[Finding]) -> List[Dict[str, str]]:
        """Build category-level remediation recommendations."""
        seen: set[str] = set()
        items: List[Dict[str, str]] = []
        for f in findings:
            if not f.is_vulnerable:
                continue
            cat = f.vulnerability.owasp_category
            if not cat or cat in seen:
                continue
            seen.add(cat)
            items.append(
                {
                    "category": cat,
                    "remediation": _REMEDIATION_KB.get(
                        cat,
                        f"Review and address {cat} findings according to OWASP LLM Top 10 guidance.",
                    ),
                }
            )
        return items

    # ------------------------------------------------------------------
    # HTML builder
    # ------------------------------------------------------------------

    def _build_html(self, findings: List[Finding]) -> str:
        """Construct a complete HTML document."""
        summary = self._compute_summary(findings)

        # Severity badges
        sev_rows = ""
        for label, count in summary["by_severity"].items():
            color = _SEVERITY_COLORS.get(label, "#666")
            sev_rows += f'<li><span style="color:{color};font-weight:bold">'
            sev_rows += f"{label}: {count}</span></li>\n"

        # Findings table
        finding_rows = ""
        for f in findings:
            sev = f.vulnerability.severity.value
            color = _SEVERITY_COLORS.get(sev, "#666")
            badge = _SEVERITY_BADGE.get(sev, sev)
            vuln_tag = (
                '<span style="color:#dc3545;font-weight:bold">VULNERABLE</span>'
                if f.is_vulnerable
                else '<span style="color:#28a745">PASS</span>'
            )
            finding_rows += f"""<tr>
  <td><span style="color:{color};font-weight:bold">{badge}</span></td>
  <td>{self._esc(f.vulnerability.name)}</td>
  <td>{self._esc(f.vulnerability.owasp_category or "—")}</td>
  <td>{vuln_tag}</td>
  <td>{f.cvss_score:.1f}</td>
  <td>{self._esc(f.vulnerability.mitigation or "Review and remediate")}</td>
</tr>\n"""

        # Remediation section
        remediation_html = ""
        if self._include_remediation:
            for rec in self._build_remediation(findings):
                remediation_html += f"""
    <div class="remediation-card">
      <h3>{self._esc(rec['category'])}</h3>
      <p>{self._esc(rec['remediation'])}</p>
    </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{self._esc(self._title)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f8f9fa; color: #212529; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ color: #dc3545; border-bottom: 3px solid #dc3545; padding-bottom: 10px; }}
  h2 {{ color: #495057; margin-top: 30px; }}
  .summary-card {{ display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }}
  .card {{ flex: 1; min-width: 200px; background: #fff; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
  .card h3 {{ margin: 0 0 10px; color: #495057; }}
  .card .value {{ font-size: 2em; font-weight: bold; color: #dc3545; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }}
  thead {{ background: #343a40; color: white; }}
  th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
  tr:hover {{ background: #f1f3f5; }}
  .remediation-card {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 10px 0; border-radius: 4px; }}
  .remediation-card h3 {{ margin: 0 0 8px; color: #856404; }}
  ul {{ list-style: none; padding: 0; }}
  ul li {{ padding: 4px 0; }}
  .footer {{ margin-top: 40px; padding: 20px; text-align: center; color: #6c757d; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ {self._esc(self._title)}</h1>
  <p>Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")} &middot; Framework v2.0.0</p>

  <div class="summary-card">
    <div class="card">
      <h3>Total Findings</h3>
      <div class="value">{summary['total_findings']}</div>
    </div>
    <div class="card">
      <h3>Vulnerable</h3>
      <div class="value" style="color:dc3545">{summary['total_vulnerable']}</div>
    </div>
    <div class="card">
      <h3>Avg CVSS</h3>
      <div class="value">{summary['average_cvss']:.1f}</div>
    </div>
    <div class="card">
      <h3>Worst Severity</h3>
      <div class="value" style="color:{_SEVERITY_COLORS.get(summary['worst_severity'], '#666')}">{summary['worst_severity']}</div>
    </div>
  </div>

  <h2>Severity Breakdown</h2>
  <ul>{sev_rows}</ul>

  <h2>Detailed Findings</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>Name</th><th>OWASP</th><th>Status</th><th>CVSS</th><th>Remediation</th></tr>
    </thead>
    <tbody>
{finding_rows}    </tbody>
  </table>

  {remediation_html}

  <div class="footer">
    Generated by AI Security Framework v2.0.0 &middot; OWASP LLM Top 10 &middot;
    <a href="https://genai.owasp.org/llm-top-10/" style="color:#0d6efd">OWASP LLM Top 10 Reference</a>
  </div>
</div>
</body>
</html>"""

    # ------------------------------------------------------------------
    # Markdown builder
    # ------------------------------------------------------------------

    def _build_markdown(self, findings: List[Finding]) -> str:
        """Construct a Markdown document."""
        summary = self._compute_summary(findings)
        lines: List[str] = [
            f"# {self._title}",
            "",
            f"_Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · "
            f"Framework v2.0.0_",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Findings | {summary['total_findings']} |",
            f"| Vulnerable | {summary['total_vulnerable']} |",
            f"| Passed | {summary['total_passed']} |",
            f"| Average CVSS | {summary['average_cvss']:.1f} |",
            f"| Worst Severity | {summary['worst_severity']} |",
            "",
            "## Severity Breakdown",
            "",
        ]
        for label, count in summary["by_severity"].items():
            badge = _SEVERITY_BADGE.get(label, label)
            lines.append(f"- {badge}: {count}")
        lines.append("")

        lines += [
            "## Detailed Findings",
            "",
            "| # | Severity | Name | OWASP | CVSS | Status |",
            "|---|----------|------|-------|------|--------|",
        ]
        for idx, f in enumerate(findings, 1):
            sev = f.vulnerability.severity.value
            badge = _SEVERITY_BADGE.get(sev, sev)
            status = "⚠️ FAIL" if f.is_vulnerable else "✅ PASS"
            lines.append(
                f"| {idx} | {badge} | {self._md_esc(f.vulnerability.name)} "
                f"| {f.vulnerability.owasp_category or '—'} | {f.cvss_score:.1f} "
                f"| {status} |"
            )

        lines += ["", "## Vulnerable Details", ""]
        for idx, f in enumerate(findings, 1):
            if f.is_vulnerable:
                badge = _SEVERITY_BADGE.get(f.vulnerability.severity.value, "—")
                lines.append(f"### {idx}. {badge} — {self._md_esc(f.vulnerability.name)}")
                lines.append("")
                lines.append(f"- **OWASP Category:** {f.vulnerability.owasp_category or 'N/A'}")
                lines.append(f"- **CVSS Score:** {f.cvss_score:.1f}")
                lines.append(f"- **Description:** {self._md_esc(f.vulnerability.description)}")
                lines.append(
                    f"- **Remediation:** "
                    f"{self._md_esc(f.vulnerability.mitigation or 'Review and remediate')}"
                )
                lines.append("")

        if self._include_remediation:
            rem = self._build_remediation(findings)
            if rem:
                lines += ["## Remediation Recommendations", ""]
                for r in rem:
                    lines.append(f"### {self._md_esc(r['category'])}")
                    lines.append("")
                    lines.append(r["remediation"])
                    lines.append("")

        lines += [
            "---",
            "*Generated by AI Security Framework v2.0.0*",
            f"[OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/)",
        ]
        return "\n".join(lines)

    @staticmethod
    def _esc(text: str) -> str:
        """Escape for HTML attribute/text content."""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    @staticmethod
    def _md_esc(text: str) -> str:
        """Escape pipe and angle brackets for Markdown tables."""
        return text.replace("|", "\\|").replace("<", "").replace(">", "")
