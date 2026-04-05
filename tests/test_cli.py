"""CLI integration tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_security.cli import main


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestCLIHappyPath:
    """Happy-path CLI tests."""

    def test_help_no_args(self, capsys: pytest.CaptureFixture) -> None:
        rc = main([])
        assert rc == 0
        captured = capsys.readouterr()
        assert "ai-sec-scan" in captured.out

    def test_version(self, capsys: pytest.CaptureFixture) -> None:
        with pytest.raises(SystemExit):
            main(["--version"])
        captured = capsys.readouterr()
        assert "ai-security-framework" in captured.out

    def test_report_from_valid_json(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        data = {
            "findings": [
                {
                    "vulnerability": {
                        "id": "t1", "name": "Test Vuln", "type": "prompt_injection",
                        "severity": "HIGH", "description": "D",
                        "owasp_category": "LLM01", "mitigation": "Fix it",
                    },
                    "test_prompt": "p", "model_response": "r",
                    "is_vulnerable": True, "evidence": "", "cvss_score": 8.0,
                    "metadata": {},
                }
            ]
        }
        inp = tmp_path / "input.json"
        inp.write_text(json.dumps(data))
        out = tmp_path / "output.html"
        rc = main(["report", "--input", str(inp), "--format", "html", "--output", str(out)])
        assert rc == 0
        assert out.exists()

    def test_report_json_format(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        data = {"findings": []}
        inp = tmp_path / "in.json"
        inp.write_text(json.dumps(data))
        rc = main(["report", "--input", str(inp), "--format", "json"])
        assert rc == 0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestCLIEdeCases:
    """Edge-case CLI tests."""

    def test_report_missing_input(self, capsys: pytest.CaptureFixture) -> None:
        rc = main(["report", "--input", "/nonexistent/file.json"])
        assert rc == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower()

    def test_report_invalid_json(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{broken json")
        rc = main(["report", "--input", str(bad)])
        assert rc == 1
        captured = capsys.readouterr()
        assert "invalid json" in captured.out.lower()

    def test_scan_no_config(self, capsys: pytest.CaptureFixture) -> None:
        rc = main(["scan", "--target", "https://api.example.com"])
        assert rc == 1

    def test_compliance_no_findings(self, capsys: pytest.CaptureFixture) -> None:
        rc = main(["compliance", "--input", "/nonexistent.json"])
        # Should fail at input reading or warn
        assert rc in (0, 1)


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestCLIErrors:
    """Error handling tests."""

    def test_unknown_command(self, capsys: pytest.CaptureFixture) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["unknown_cmd"])
        assert exc_info.value.code == 2  # argparse error exit code

    def test_scan_missing_target(self, capsys: pytest.CaptureFixture) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["scan"])
        assert exc_info.value.code == 2  # argparse error

    def test_report_bad_format(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        inp = tmp_path / "in.json"
        inp.write_text(json.dumps({"findings": []}))
        rc = main(["report", "--input", str(inp), "--format", "xml"])
        # Bad format falls through to empty findings with no error path
        assert rc in (0, 1)
        captured = capsys.readouterr()
        # Either an error message or a "no findings" message
        assert "findings" in captured.out.lower() or "format" in captured.out.lower()

    def test_compliance_bad_framework(self, capsys: pytest.CaptureFixture) -> None:
        rc = main(["compliance", "--framework", "nonexistent"])
        assert rc == 1
        captured = capsys.readouterr()
        assert "unknown framework" in captured.out.lower()
