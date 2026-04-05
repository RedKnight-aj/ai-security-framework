"""
AI Security Framework — Public API
===================================

Production-grade security testing for AI/LLM systems.
Tests against OWASP LLM Top 10, NIST AI RMF, and custom attack patterns.

Example Usage::

    from ai_security import SecurityScanner, ComplianceAuditor
    from ai_security import ReportGenerator

    scanner = SecurityScanner(target="https://api.example.com/v1/chat")
    findings = scanner.run_scan()

    auditor = ComplianceAuditor()
    report = auditor.audit(findings, framework="owasp")

    reporter = ReportGenerator()
    reporter.to_html(findings, output_path="report.html")

:copyright: (c) 2026 RedKnight AI
:license: MIT
"""

from __future__ import annotations

from .scanner import (
    Finding,
    SecurityScanner,
    Severity,
    Vulnerability,
    VulnerabilityType,
)
from .redteam import AttackPlugin, AttackResult, AttackStrategy, RedTeam
from .reporter import ReportFormat, ReportGenerator
from .compliance import ComplianceAuditor, ComplianceReport, ComplianceFramework
from .config import Settings

__version__ = "2.0.0"
__author__ = "RedKnight AI"
__license__ = "MIT"

__all__ = [
    # Core classes
    "SecurityScanner",
    "RedTeam",
    "ReportGenerator",
    "ComplianceAuditor",
    # Enums & types
    "Finding",
    "Severity",
    "Vulnerability",
    "VulnerabilityType",
    "AttackResult",
    "AttackStrategy",
    "AttackPlugin",
    "ComplianceReport",
    "ComplianceFramework",
    "ReportFormat",
    # Config
    "Settings",
    # Metadata
    "__version__",
]
