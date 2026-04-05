"""Unit tests for SecurityScanner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ai_security.scanner import (
    Finding,
    SecurityScanner,
    Severity,
    Vulnerability,
    VulnerabilityType,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_finding(
    vuln_id: str = "test_001",
    name: str = "Test Vuln",
    sev: Severity = Severity.HIGH,
    is_vuln: bool = True,
    cvss: float = 7.5,
    owasp: str = "LLM01",
) -> Finding:
    return Finding(
        vulnerability=Vulnerability(
            id=vuln_id,
            name=name,
            type=VulnerabilityType.PROMPT_INJECTION,
            severity=sev,
            description="Test",
            owasp_category=owasp,
            mitigation="Test mitigation",
        ),
        test_prompt="test prompt",
        model_response="test response",
        is_vulnerable=is_vuln,
        cvss_score=cvss,
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestSecurityScannerHappyPath:
    """Tests for the happy path."""

    def test_scanner_initializes(self) -> None:
        s = SecurityScanner(target="https://example.com")
        assert s._target == "https://example.com"

    def test_scanner_with_settings(self) -> None:
        from ai_security.config import Settings

        settings = Settings(target="https://api.test.com", timeout_sec=120)
        s = SecurityScanner(settings=settings)
        assert s._settings.timeout_sec == 120
        assert s._settings.target == "https://api.test.com"

    def test_severity_sort_key(self) -> None:
        assert Severity.INFO.sort_key == 0
        assert Severity.LOW.sort_key == 1
        assert Severity.MEDIUM.sort_key == 2
        assert Severity.HIGH.sort_key == 3
        assert Severity.CRITICAL.sort_key == 4

    def test_finding_to_dict(self) -> None:
        f = _make_finding()
        d = f.to_dict()
        assert d["vulnerability"]["id"] == "test_001"
        assert d["is_vulnerable"] is True
        assert d["cvss_score"] == 7.5

    def test_vulnerability_to_dict(self) -> None:
        v = Vulnerability(
            id="v1",
            name="Test",
            type=VulnerabilityType.JAILBREAK,
            severity=Severity.CRITICAL,
            description="Desc",
            owasp_category="LLM01",
        )
        d = v.to_dict()
        assert d["type"] == "jailbreak"
        assert d["severity"] == "CRITICAL"

    def test_list_owasp_configs(self) -> None:
        """Should list bundled config names if the directory exists."""
        from ai_security.config import Settings

        s = SecurityScanner(target="https://example.com")
        names = s.list_owasp_configs()
        # Should return list (possibly empty if not installed as package)
        assert isinstance(names, list)

    def test_list_quick_start_configs(self) -> None:
        s = SecurityScanner(target="https://example.com")
        names = s.list_quick_start_configs()
        assert isinstance(names, list)


# ---------------------------------------------------------------------------
# run_scan
# ---------------------------------------------------------------------------


class TestRunScan:
    """Tests for run_scan."""

    def test_raises_on_empty_args(self) -> None:
        s = SecurityScanner(target="")
        with pytest.raises(ValueError, match="no target URL"):
            s.run_scan()

    @patch.object(SecurityScanner, "run_promptfoo_eval")
    @patch.object(SecurityScanner, "_find_promptfoo")
    def test_run_scan_with_categories(
        self, mock_find: MagicMock, mock_eval: MagicMock
    ) -> None:
        mock_find.return_value = "/usr/bin/promptfoo"
        mock_eval.return_value = (
            0,
            json.dumps({"results": []}),
            "",
        )
        s = SecurityScanner(target="https://api.example.com")
        # This calls _run_single_config which calls run_promptfoo_eval
        findings = s.run_scan(categories=["LLM01"])
        assert isinstance(findings, list)

    def test_raises_on_bad_quick_start(self) -> None:
        s = SecurityScanner(target="https://api.example.com")
        with pytest.raises(FileNotFoundError):
            s.run_scan(quick_start="nonexistent-config")


# ---------------------------------------------------------------------------
# _parse_promptfoo_output
# ---------------------------------------------------------------------------


class TestParsePromptfooOutput:
    """Tests for output parsing."""

    def test_valid_json(self) -> None:
        s = SecurityScanner(target="https://example.com")
        data = json.dumps({
            "results": {"body": {"results": [
                {
                    "vars": {"prompt": "test", "metadata": {"category": "LLM01", "severity": "HIGH"}},
                    "response": {"text": "vulnerable response"},
                    "metrics": {"score": 0.3, "fail": True},
                }
            ]}},
        })
        findings = s._parse_promptfoo_output(data, "test_config")
        assert len(findings) >= 1
        assert findings[0].is_vulnerable is True

    def test_invalid_json(self) -> None:
        s = SecurityScanner(target="https://example.com")
        findings = s._parse_promptfoo_output("not json", "err")
        assert len(findings) == 1
        assert "parse failure" in findings[0].vulnerability.name.lower()

    def test_empty_json(self) -> None:
        s = SecurityScanner(target="https://example.com")
        findings = s._parse_promptfoo_output("{}", "empty")
        # Empty JSON object → treated as valid but no rows, could return parse-fallback or empty
        assert isinstance(findings, list)

    def test_list_results(self) -> None:
        s = SecurityScanner(target="https://example.com")
        # Wrap the list in a results dict for the parser
        data = json.dumps({"results": [
            {
                "vars": {"prompt": "hi", "metadata": {"category": "LLM01"}},
                "response": {"text": "ok"},
                "metrics": {"score": 0.9, "fail": False},
            }
        ]})
        findings = s._parse_promptfoo_output(data, "list_test")
        assert len(findings) >= 1
        assert findings[0].is_vulnerable is False


# ---------------------------------------------------------------------------
# Edge cases / errors
# ---------------------------------------------------------------------------


class TestSecurityScannerErrors:
    """Tests for error handling."""

    def test_target_type_error(self) -> None:
        with pytest.raises(TypeError, match="target must be a string"):
            SecurityScanner(target=123)  # type: ignore[arg-type]

    @patch.object(SecurityScanner, "_find_promptfoo")
    def test_find_promptfoo_raises(self, mock_find: MagicMock) -> None:
        mock_find.side_effect = FileNotFoundError("promptfoo missing")
        s = SecurityScanner(target="https://example.com")
        with pytest.raises(FileNotFoundError):
            s.run_promptfoo_eval("config.yml")

    @patch("shutil.which")
    def test_find_promptfoo_missing(self, mock_which: MagicMock) -> None:
        mock_which.return_value = None
        s = SecurityScanner(target="https://example.com")
        with pytest.raises(FileNotFoundError, match="Promptfoo is not installed"):
            s._find_promptfoo()

    @patch.object(SecurityScanner, "_find_promptfoo")
    @patch("subprocess.run")
    def test_promptfoo_timeout(
        self, mock_run: MagicMock, mock_find: MagicMock
    ) -> None:
        import subprocess

        mock_find.return_value = "/usr/bin/promptfoo"
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["promptfoo"], timeout=600)
        s = SecurityScanner(target="https://example.com")
        # With single max_retries=1, should return timeout finding
        s._settings.max_retries = 1
        findings = s._run_single_config("config.yml", "timeout_test")
        assert len(findings) == 1
        assert "timeout" in findings[0].vulnerability.name.lower()

    @patch.object(SecurityScanner, "_find_promptfoo")
    @patch("subprocess.run")
    def test_promptfoo_nonzero_exit(
        self, mock_run: MagicMock, mock_find: MagicMock
    ) -> None:
        mock_find.return_value = "/usr/bin/promptfoo"
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        s = SecurityScanner(target="https://example.com")
        s._settings.max_retries = 1
        findings = s._run_single_config("config.yml", "fail_test")
        assert len(findings) == 1
        assert "failed" in findings[0].vulnerability.name.lower()
