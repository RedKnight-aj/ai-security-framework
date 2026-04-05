"""Unit tests for ComplianceAuditor."""

from __future__ import annotations

from pathlib import Path

import pytest

from ai_security.compliance import ComplianceAuditor, ComplianceFramework, ComplianceReport
from ai_security.scanner import (
    Finding,
    Severity,
    Vulnerability,
    VulnerabilityType,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fail_finding(cat: str = "LLM01") -> Finding:
    return Finding(
        vulnerability=Vulnerability(
            id="cf1",
            name="Compliance failure",
            type=VulnerabilityType.PROMPT_INJECTION,
            severity=Severity.HIGH,
            description="Failed audit test",
            owasp_category=cat,
            mitigation="Fix it",
        ),
        test_prompt="",
        model_response="",
        is_vulnerable=True,
        cvss_score=8.0,
    )


def _make_pass_finding(cat: str = "LLM02") -> Finding:
    return Finding(
        vulnerability=Vulnerability(
            id="cp1",
            name="Compliance pass",
            type=VulnerabilityType.ADVERSARIAL,
            severity=Severity.LOW,
            description="Passed audit test",
            owasp_category=cat,
            mitigation="",
        ),
        test_prompt="",
        model_response="",
        is_vulnerable=False,
        cvss_score=1.0,
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestComplianceAuditorHappyPath:
    """Happy-path tests."""

    def test_audit_owasp_with_failures(self) -> None:
        auditor = ComplianceAuditor()
        findings = [_make_fail_finding("LLM01")]
        report = auditor.audit(findings, framework="owasp")
        assert isinstance(report, ComplianceReport)
        assert report.framework == "OWASP LLM Top 10"
        assert report.failed > 0
        assert report.overall_status == "FAIL"

    def test_audit_owasp_all_pass(self) -> None:
        auditor = ComplianceAuditor()
        # Need to have no vulns AND no warnings (all 10 categories present with no vulns)
        findings = [_make_pass_finding(f"LLM{i:02d}") for i in range(1, 11)]
        report = auditor.audit(findings, framework="owasp")
        assert report.overall_status == "PASS"
        assert report.failed == 0

    def test_audit_nist(self) -> None:
        auditor = ComplianceAuditor()
        findings = [_make_fail_finding("LLM01"), _make_fail_finding("LLM06")]
        report = auditor.audit(findings, framework="nist_ai_rmf")
        assert isinstance(report, ComplianceReport)
        assert "NIST" in report.framework
        assert report.failed > 0

    def test_report_to_dict(self) -> None:
        auditor = ComplianceAuditor()
        findings = [_make_fail_finding("LLM01")]
        report = auditor.audit(findings, framework="owasp")
        d = report.to_dict()
        assert d["framework"] == "OWASP LLM Top 10"
        assert isinstance(d["categories"], list)
        assert isinstance(d["recommendations"], list)

    def test_category_has_recommendations_on_fail(self) -> None:
        auditor = ComplianceAuditor()
        findings = [_make_fail_finding("LLM01")]
        report = auditor.audit(findings, framework="owasp")
        llm01_cat = next(c for c in report.categories if c.category_id == "LLM01")
        assert llm01_cat.status == "FAIL"
        assert len(llm01_cat.recommendations) > 0

    def test_warned_category(self) -> None:
        auditor = ComplianceAuditor()
        # Empty findings → all categories should be warned
        report = auditor.audit([], framework="owasp")
        assert report.overall_status == "WARN"
        assert report.failed == 0
        assert report.warned > 0

    def test_score_range(self) -> None:
        auditor = ComplianceAuditor()
        findings = [_make_fail_finding("LLM01")]
        report = auditor.audit(findings, framework="owasp")
        assert 0.0 <= report.score <= 100.0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestComplianceAuditorEdgeCases:
    """Edge-case tests."""

    def test_multiple_categories(self) -> None:
        auditor = ComplianceAuditor()
        findings = [
            _make_fail_finding("LLM01"),
            _make_fail_finding("LLM02"),
            _make_pass_finding("LLM03"),
        ]
        report = auditor.audit(findings, framework="owasp")
        assert report.failed == 2
        assert report.passed == 1

    def test_unknown_owasp_category(self) -> None:
        findings = [
            Finding(
                vulnerability=Vulnerability(
                    id="x1", name="X", type=VulnerabilityType.ADVERSARIAL,
                    severity=Severity.LOW, description="D",
                    owasp_category="LLM99",
                ),
                test_prompt="", model_response="", is_vulnerable=False,
            )
        ]
        auditor = ComplianceAuditor()
        report = auditor.audit(findings, framework="owasp")
        # Category not in map → all other categories are WARN (no findings)
        assert isinstance(report, ComplianceReport)
        assert report.overall_status == "WARN"  # all unmapped categories are WARN


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TestComplianceAuditorErrors:
    """Error handling tests."""

    def test_invalid_framework_raises(self) -> None:
        auditor = ComplianceAuditor()
        with pytest.raises(ValueError, match="Unknown framework"):
            auditor.audit([], framework="totally_fake")

    def test_data_file_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import tempfile
        auditor = ComplianceAuditor()
        with tempfile.TemporaryDirectory() as td:
            auditor._settings.data_dir = td  # empty dir → no files
            with pytest.raises(FileNotFoundError, match="Vulnerability database"):
                auditor.load_vulnerability_database()

    def test_attack_patterns_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import tempfile
        auditor = ComplianceAuditor()
        with tempfile.TemporaryDirectory() as td:
            auditor._settings.data_dir = td
            with pytest.raises(FileNotFoundError, match="Attack patterns"):
                auditor.load_attack_patterns()

    def test_resolve_framework_string(self) -> None:
        assert ComplianceAuditor._resolve_framework("owasp") == ComplianceFramework.OWASP
        assert ComplianceAuditor._resolve_framework("NIST-AI-RMF") == ComplianceFramework.NIST_AI_RMF
        assert ComplianceAuditor._resolve_framework(ComplianceFramework.OWASP) == ComplianceFramework.OWASP
