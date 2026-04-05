"""
Command-line interface for the AI Security Framework.

Four subcommands::

    ai-sec-scan scan        --target <url> --config <file>
    ai-sec-scan redteam     --target <url> --strategy <strategy>
    ai-sec-scan report      --input  <results.json> --format html
    ai-sec-scan compliance  --target <url> --framework owasp
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme

from . import __version__
from .scanner import Finding, SecurityScanner, Severity, Vulnerability, VulnerabilityType
from .redteam import RedTeam
from .reporter import ReportFormat, ReportGenerator
from .compliance import ComplianceAuditor, ComplianceFramework
from .config import Settings

# ---------------------------------------------------------------------------
# Rich console with custom theme
# ---------------------------------------------------------------------------

_THEME = Theme(
    {
        "critical": "bold red",
        "high": "bold orange_red1",
        "medium": "bold yellow",
        "low": "bold green",
        "info": "bold cyan",
        "pass": "bold green",
        "fail": "bold red",
        "warn": "bold yellow",
    }
)

console = Console(theme=_THEME)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER = """
  _ _    _ _____  _____ ______ _______ _____ _   _  _____
 | | |  | |  __ \\|_   _||  ____|__   __|_   _| \\ | |/ ____|
 | | |  | | |__) | | |  | |__     | |    | | |  \\| | |  __
 | | |  | |  _  /  | |  |  __|    | |    | | | . ` | | |_ |
 | | |__| | | \\ \\ _| |_ | |____   | |   _| |_| |\\  | |__| |
  \\____/|_|  \\_\\|_____||______|  |_|  |_____|_| \\_|\\_____|
                     AI Security Framework v{version}
""".strip()


# ---------------------------------------------------------------------------
# Helpers to build Finding objects from CLI (for report-only mode)
# ---------------------------------------------------------------------------


def _findings_from_dict(data: dict) -> List[Finding]:
    """Reconstruct Finding objects from a JSON report dict."""
    findings: List[Finding] = []
    raw_findings = data.get("findings", [])
    for item in raw_findings:
        if isinstance(item, dict):
            vuln_data = item.get("vulnerability", {})
            try:
                sev = Severity(str(vuln_data.get("severity", "INFO")))
            except ValueError:
                sev = Severity.INFO
            try:
                vtype = VulnerabilityType(str(vuln_data.get("type", "adversarial")))
            except ValueError:
                vtype = VulnerabilityType.ADVERSARIAL

            vuln = Vulnerability(
                id=str(vuln_data.get("id", "unknown")),
                name=str(vuln_data.get("name", "Unknown")),
                type=vtype,
                severity=sev,
                description=str(vuln_data.get("description", "")),
                owasp_category=str(vuln_data.get("owasp_category", "")),
                mitigation=str(vuln_data.get("mitigation", "")),
            )
            findings.append(
                Finding(
                    vulnerability=vuln,
                    test_prompt=str(item.get("test_prompt", "")),
                    model_response=str(item.get("model_response", "")),
                    is_vulnerable=bool(item.get("is_vulnerable", False)),
                    evidence=str(item.get("evidence", "")),
                    cvss_score=float(item.get("cvss_score", 0.0)),
                    metadata=item.get("metadata", {}),
                )
            )
    return findings


def _print_findings_table(findings: List[Finding]) -> None:
    """Render a Rich table of findings."""
    table = Table(
        title="Security Findings",
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Name", width=30)
    table.add_column("OWASP", width=8)
    table.add_column("CVSS", width=6)
    table.add_column("Status", width=8)

    for idx, f in enumerate(findings, 1):
        sev = f.vulnerability.severity.value
        sev_style = sev.lower()
        status = "[fail]FAIL[/fail]" if f.is_vulnerable else "[pass]PASS[/pass]"
        table.add_row(
            str(idx),
            f"[{sev_style}]{sev}[/{sev_style}]",
            f.vulnerability.name,
            f.vulnerability.owasp_category or "—",
            f"{f.cvss_score:.1f}",
            status,
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def _cmd_scan(args: argparse.Namespace) -> int:
    """Handle the ``scan`` subcommand."""
    console.print(Panel(_BANNER.format(version=__version__), style="bold blue"))

    settings = Settings.from_env()
    if args.target:
        settings.target = args.target
    settings.timeout_sec = args.timeout

    scanner = SecurityScanner(target=settings.target, settings=settings)

    config_files: Optional[List[str]] = (
        args.config if hasattr(args, "config") and args.config else None
    )
    quick_start: Optional[str] = (
        args.quick_start if hasattr(args, "quick_start") and args.quick_start else None
    )

    if not config_files and not quick_start:
        # If no config specified and target is set, list available configs
        console.print("\n[yellow]No config specified. Listing available configs...[/yellow]")
        console.print(f"\n[cyan]OWASP configs:[/cyan] {scanner.list_owasp_configs()}")
        console.print(f"[cyan]Quick-start:[/cyan] {scanner.list_quick_start_configs()}")
        console.print("\n[yellow]Use --quick-start or --config to begin scanning.[/yellow]")
        return 1

    try:
        findings = scanner.run_scan(
            config_files=config_files,
            categories=args.category if args.category else None,
            quick_start=quick_start,
        )
    except Exception as exc:
        console.print(f"\n[critical]Scan failed: {exc}[/critical]")
        return 1

    if not findings:
        console.print("\n[green]No findings. Target appears clean.[/green]")
        return 0

    _print_findings_table(findings)

    # Summary
    vuln_count = sum(1 for f in findings if f.is_vulnerable)
    console.print(
        f"\nTotal: {len(findings)} findings · "
        f"[critical]{vuln_count} vulnerable[/critical] · "
        f"[green]{len(findings) - vuln_count} passed[/green]"
    )
    return 0


def _cmd_redteam(args: argparse.Namespace) -> int:
    """Handle the ``redteam`` subcommand."""
    console.print(Panel(_BANNER.format(version=__version__), style="bold blue"))

    settings = Settings.from_env()
    if args.target:
        settings.target = args.target

    redteam = RedTeam(target=settings.target, settings=settings)
    plugins = args.plugins.split(",") if args.plugins else ["default"]

    strategies = args.strategy.split(",") if args.strategy else None

    console.print(f"\n[cyan]Launching red-team campaign...[/cyan]")
    console.print(f"  Target: {settings.target}")
    console.print(f"  Plugins: {plugins}")
    console.print(f"  Strategies: {strategies or 'default'}")

    try:
        findings = redteam.run(plugins=plugins, strategies=strategies)
    except Exception as exc:
        console.print(f"\n[critical]Red-team failed: {exc}[/critical]")
        return 1

    _print_findings_table(findings)

    report = redteam.generate_report(findings)
    console.print(
        Panel(
            f"Total Attacks: {report['summary']['total_tests']} · "
            f"Vulnerable: {report['summary']['vulnerabilities_found']} · "
            f"Passed: {report['summary']['passed']}",
            title="Red-Team Summary",
            border_style="red",
        )
    )

    if args.output:
        reporter = ReportGenerator()
        path = reporter.to_json(findings, args.output)
        console.print(f"\n[green]Results saved to {path}[/green]")

    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    """Handle the ``report`` subcommand."""
    console.print(Panel(_BANNER.format(version=__version__), style="bold blue"))

    input_path = Path(args.input)
    if not input_path.exists():
        console.print(f"[critical]Input file not found: {input_path}[/critical]")
        return 1

    with input_path.open("r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            console.print(f"[critical]Invalid JSON in {input_path}: {exc}[/critical]")
            return 1

    findings = _findings_from_dict(data)
    if not findings:
        console.print("[yellow]No findings found in input file.[/yellow]")
        return 0

    _print_findings_table(findings)

    fmt_str = args.format.lower()
    try:
        fmt = ReportFormat(fmt_str)
    except ValueError:
        console.print(
            f"[critical]Unknown format: {fmt_str!r}. "
            f"Use json, html, or markdown.[/critical]"
        )
        return 1

    reporter = ReportGenerator()
    ext_map = {"json": ".json", "html": ".html", "markdown": ".md"}
    output_path = args.output or f"report{ext_map.get(fmt_str, '.txt')}"
    path = reporter.save(findings, fmt, output_path)

    console.print(f"\n[green]{fmt.value.upper()} report saved to {path}[/green]")
    return 0


def _cmd_compliance(args: argparse.Namespace) -> int:
    """Handle the ``compliance`` subcommand."""
    console.print(Panel(_BANNER.format(version=__version__), style="bold blue"))

    auditor = ComplianceAuditor()

    framework_str = args.framework if args.framework else "owasp"
    try:
        framework = ComplianceFramework(framework_str.lower().replace(" ", "_"))
    except ValueError:
        console.print(
            f"[critical]Unknown framework: {framework_str!r}. "
            f"Use owasp or nist_ai_rmf.[/critical]"
        )
        return 1

    # Scan first if a target is provided
    findings: List[Finding] = []
    if args.target:
        settings = Settings.from_env()
        settings.target = args.target
        scanner = SecurityScanner(target=args.target, settings=settings)
        categories_arg: Optional[List[str]] = None
        if framework == ComplianceFramework.OWASP:
            categories_arg = [f"LLM{i:02d}" for i in range(1, 11)]
        try:
            findings = scanner.run_scan(categories=categories_arg)
        except Exception as exc:
            console.print(
                f"[yellow]Scan failed ({exc}), generating compliance from bundled data only.[/yellow]"
            )
    elif args.input:
        input_path = Path(args.input)
        if input_path.exists():
            with input_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            findings = _findings_from_dict(data)

    if not findings:
        console.print("[yellow]No findings to audit. Run a scan first.[/yellow]")
        return 1

    try:
        report = auditor.audit(findings, framework=framework)
    except Exception as exc:
        console.print(f"[critical]Compliance audit failed: {exc}[/critical]")
        return 1

    # Print results
    status_style = {
        "PASS": "green",
        "FAIL": "red",
        "WARN": "yellow",
    }.get(report.overall_status, "white")

    summary = Table(
        title=f"Compliance Report — {report.framework}",
        show_header=True,
        header_style="bold magenta",
    )
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value")
    summary.add_row("Overall Status", f"[{status_style}]{report.overall_status}[/{status_style}]")
    summary.add_row("Score", f"{report.score:.1f} / 100.0")
    summary.add_row("Categories Passed", str(report.passed))
    summary.add_row("Categories Failed", str(report.failed))
    summary.add_row("Categories Warned", str(report.warned))
    console.print(summary)

    console.print("\n[cyan]Category Details:[/cyan]")
    for cat in report.categories:
        c_style = status_style if cat.status in status_style else "white"
        console.print(f"  [{c_style}]{cat.status}[/{c_style}] {cat.category_id} — {cat.name}")
        for rec in cat.recommendations[:2]:
            console.print(f"    → {rec}")

    if args.output:
        with Path(args.output).open("w", encoding="utf-8") as fh:
            json.dump(report.to_dict(), fh, indent=2, default=str)
        console.print(f"\n[green]Compliance report saved to {args.output}[/green]")

    return 0


# ---------------------------------------------------------------------------
# Argparse setup
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="ai-sec-scan",
        description="AI Security Framework — Production-grade LLM security testing",
        epilog="Examples:\n"
               "  ai-sec-scan scan --target https://api.example.com --quick-start basic-scan\n"
               "  ai-sec-scan redteam --target https://api.example.com --plugin injection,jailbreak\n"
               "  ai-sec-scan report --input results.json --format html\n"
               "  ai-sec-scan compliance --target https://api.example.com --framework owasp\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"ai-security-framework {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan ---
    scan_p = subparsers.add_parser("scan", help="Run security scans against a target")
    scan_p.add_argument("--target", required=True, help="Target URL or API endpoint")
    scan_p.add_argument("--config", nargs="+", help="Promptfoo YAML config file(s)")
    scan_p.add_argument("--quick-start", help="Quick-start config name (e.g. basic-scan)")
    scan_p.add_argument("--category", nargs="+", help="OWASP LLM category codes (e.g. LLM01)")
    scan_p.add_argument(
        "--timeout", type=int, default=600, help="Timeout in seconds (default: 600)"
    )
    scan_p.set_defaults(func=_cmd_scan)

    # --- redteam ---
    rt_p = subparsers.add_parser("redteam", help="Launch red-team attack simulation")
    rt_p.add_argument("--target", required=True, help="Target URL or API endpoint")
    rt_p.add_argument(
        "--plugins",
        default="default",
        help="Comma-separated plugins (default: default)",
    )
    rt_p.add_argument(
        "--strategy",
        default=None,
        help="Comma-separated strategies (e.g. direct,multi_turn)",
    )
    rt_p.add_argument("--output", help="Save results to JSON file")
    rt_p.set_defaults(func=_cmd_redteam)

    # --- report ---
    rpt_p = subparsers.add_parser("report", help="Generate formatted security reports")
    rpt_p.add_argument("--input", required=True, help="Input JSON results file")
    rpt_p.add_argument(
        "--format", default="json", help="Output format: json, html, markdown (default: json)"
    )
    rpt_p.add_argument("--output", help="Output file path")
    rpt_p.set_defaults(func=_cmd_report)

    # --- compliance ---
    comp_p = subparsers.add_parser(
        "compliance", help="Run OWASP / NIST AI RMF compliance audit"
    )
    comp_p.add_argument(
        "--target", help="Target URL to scan before auditing"
    )
    comp_p.add_argument(
        "--input", help="Input JSON results file (alternative to --target)"
    )
    comp_p.add_argument(
        "--framework",
        default="owasp",
        help="Framework: owasp, nist_ai_rmf (default: owasp)",
    )
    comp_p.add_argument("--output", help="Save compliance report as JSON")
    comp_p.set_defaults(func=_cmd_compliance)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point.

    Args:
        argv: Command-line arguments (defaults to ``sys.argv[1:]``).

    Returns:
        Exit code (0 = success, 1 = error).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
