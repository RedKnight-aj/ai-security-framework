"""
Security Scanner — core vulnerability detection engine.

The :class:`SecurityScanner` class drives all OWASP LLM Top 10 tests
through **Promptfoo** (``promptfoo eval``) via the :class:`PromptfooEngine`
CLI wrapper.  It loads bundled YAML configs, invokes the engine, parses
output, and returns structured :class:`Finding` objects.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import Settings
from .engine import PromptfooEngine

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """CVSS-style severity levels, ordered low → critical."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def sort_key(self) -> int:
        """Return numeric ordering for comparison."""
        return {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }[self.value]


class VulnerabilityType(str, Enum):
    """Categories of AI/LLM vulnerabilities."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    PII_EXPOSURE = "pii_exposure"
    TOXICITY = "toxicity"
    DATA_LEAKAGE = "data_leakage"
    CONTEXT_POISONING = "context_poisoning"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    ADVERSARIAL = "adversarial"
    OVERRELIANCE = "overreliance"
    EXCESSIVE_AGENCY = "excessive_agency"
    MODEL_THEFT = "model_theft"
    SUPPLY_CHAIN = "supply_chain"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class Vulnerability:
    """Represents a known vulnerability class.

    Attributes:
        id: Unique identifier (e.g. ``CVE-2024-1234`` or ``inj_001``).
        name: Human-readable name.
        type: :class:`VulnerabilityType` for this finding.
        severity: :class:`Severity` level.
        description: Detailed description of the vulnerability.
        owasp_category: OWASP LLM category (``LLM01``-``LLM10``).
        mitigation: Recommended fix.
    """

    id: str
    name: str
    type: VulnerabilityType
    severity: Severity
    description: str
    owasp_category: str = ""
    mitigation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type.value,
            "severity": self.severity.value,
            "description": self.description,
            "owasp_category": self.owasp_category,
            "mitigation": self.mitigation,
        }


@dataclass
class Finding:
    """Single result from a security test.

    Attributes:
        vulnerability: The :class:`Vulnerability` this finding relates to.
        test_prompt: The prompt sent to the model.
        model_response: The raw response text.
        is_vulnerable: ``True`` if the model failed the test.
        evidence: Additional evidence / raw output text.
        cvss_score: Numeric CVSS score (0.0 – 10.0).
        metadata: Arbitrary dict of extra data.
    """

    vulnerability: Vulnerability
    test_prompt: str
    model_response: str
    is_vulnerable: bool
    evidence: str = ""
    cvss_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "vulnerability": self.vulnerability.to_dict(),
            "test_prompt": self.test_prompt,
            "model_response": self.model_response,
            "is_vulnerable": self.is_vulnerable,
            "evidence": self.evidence,
            "cvss_score": self.cvss_score,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class SecurityScanner:
    """Main entry-point for AI security scanning.

    Typical workflow::

        scanner = SecurityScanner(target="https://api.example.com/v1/chat")
        findings = scanner.run_scan()

    Under the hood this class invokes ``promptfoo eval`` for each OWASP LLM
    category that has a bundled YAML config.  Results are parsed and returned
    as a list of :class:`Finding` objects.

    Args:
        target: URL or API endpoint to scan.
        settings: Optional :class:`Settings` object. If *None*, defaults are
                  used.
    """

    def __init__(
        self,
        target: str = "",
        settings: Optional[Settings] = None,
    ) -> None:
        if target:
            if not isinstance(target, str):
                raise TypeError(f"target must be a string, got {type(target).__name__}")
            self._target = target
        else:
            self._target = ""
        self._settings = settings or Settings()
        if self._target:
            self._settings.target = self._target
        # Delegate CLI operations to the engine
        self._engine = PromptfooEngine(
            timeout=self._settings.timeout_sec,
            promptfoo_path=self._settings.promptfoo_path,
        )

    # ------------------------------------------------------------------
    # Dependency management
    # ------------------------------------------------------------------

    def check_dependencies(self) -> Tuple[bool, str]:
        """Check whether the Promptfoo CLI engine is available.

        Returns:
            ``(True, message)`` if available, ``(False, error_message)`` otherwise.
        """
        return self._engine.check_dependencies()

    # ------------------------------------------------------------------
    # High-level helpers
    # ------------------------------------------------------------------

    def run_promptfoo_eval(
        self,
        config_path: str | Path,
        output_path: Optional[str | Path] = None,
    ) -> Tuple[int, str, str]:
        """Run ``promptfoo eval -c <config>`` via the CLI engine.

        Args:
            config_path: Path to the YAML config to evaluate.
            output_path: Optional file path for JSON results output.

        Returns:
            Tuple of ``(return_code, stdout, stderr)``.
        """
        result = self._engine.eval(config_path=config_path, output_path=output_path)
        return result.return_code, result.stdout, result.stderr

    def _parse_promptfoo_output(self, stdout: str, config_name: str) -> List[Finding]:
        """Parse JSON stdout from Promptfoo into :class:`Finding` objects.

        Attempts to decode JSON from stdout; if that fails, returns a single
        finding indicating a parse error.

        Args:
            stdout: Raw stdout from Promptfoo.
            config_name: Name of the config that produced this output.

        Returns:
            List of parsed findings.
        """
        findings: List[Finding] = []
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, TypeError):
            # Return a meta-finding so the caller knows something happened
            findings.append(
                Finding(
                    vulnerability=Vulnerability(
                        id=f"parse_error_{config_name}",
                        name=f"Output parse failure for {config_name}",
                        type=VulnerabilityType.ADVERSARIAL,
                        severity=Severity.INFO,
                        description="Could not parse Promptfoo output as JSON",
                        owasp_category="",
                        mitigation="Run promptfoo in verbose mode for debugging",
                    ),
                    test_prompt="",
                    model_response=stdout[:500],
                    is_vulnerable=False,
                    cvss_score=0.0,
                )
            )
            return findings

        # Promptfoo output structure varies; handle the common case of
        # a top-level 'results' or 'table' key.
        results = data.get("results", data.get("table", data))
        if isinstance(results, dict):
            rows = results.get("body", {}).get("results", [])
        elif isinstance(results, list):
            rows = results
        else:
            rows = []

        severity_map: Dict[str, Severity] = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "pass": Severity.INFO,
        }

        for idx, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            vars_ = row.get("vars", {})
            metrics = row.get("metrics", {})
            grading = row.get("grading", {})

            prompt = vars_.get("prompt", vars_.get("user_input", ""))
            response = row.get("response", {}).get("text", row.get("text", ""))
            score = metrics.get("score", metrics.get("score_display", 0))
            owasp = vars_.get("metadata", {}).get("category", "")
            severity_label = vars_.get("metadata", {}).get(
                "severity", grading.get("reason", "medium")
            )
            severity_obj = severity_map.get(
                str(severity_label).lower(), Severity.MEDIUM
            )

            failed = bool(metrics.get("fail", False) or score < 0.5)

            findings.append(
                Finding(
                    vulnerability=Vulnerability(
                        id=f"pf_{config_name}_{idx}",
                        name=f"Test {idx} — {config_name}",
                        type=VulnerabilityType.PROMPT_INJECTION,
                        severity=severity_obj,
                        description=f"OWASP category {owasp}",
                        owasp_category=owasp,
                    ),
                    test_prompt=str(prompt)[:500],
                    model_response=str(response)[:500],
                    is_vulnerable=failed,
                    evidence=json.dumps(row, default=str)[:1000],
                    cvss_score=score if not failed else 7.0 + (10 - score) / 10,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Public scan API
    # ------------------------------------------------------------------

    def run_scan(
        self,
        config_files: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        quick_start: Optional[str] = None,
    ) -> List[Finding]:
        """Execute security scans against the configured target.

        One of *config_files*, *categories*, or *quick_start* must be
        supplied.

        Args:
            config_files: Explicit paths to Promptfoo YAML configs.
            categories: OWASP LLM categories to scan (e.g. ``["LLM01",
                "LLM02"]``).  Corresponding bundled configs are used.
            quick_start: Name of a quick-start config (e.g. ``"basic-scan"``).

        Returns:
            List of :class:`Finding` objects.

        Raises:
            ValueError: If the target is empty and no configs are provided.
        """
        if not self._settings.target and not config_files and not quick_start:
            raise ValueError(
                "Cannot run scan: no target URL configured. "
                "Provide target= on construction or pass explicit config_files."
            )

        all_findings: List[Finding] = []

        # --- Quick-start path ---
        if quick_start:
            qs_dir = self._settings._resolve_quick_start_dir()
            config_file = qs_dir / f"{quick_start}.yml"
            if config_file.is_file():
                findings = self._run_single_config(str(config_file), quick_start)
                all_findings.extend(findings)
            else:
                raise FileNotFoundError(f"Quick-start config not found: {config_file}")

        # --- Explicit config paths ---
        if config_files:
            for cf in config_files:
                findings = self._run_single_config(cf, Path(cf).stem)
                all_findings.extend(findings)

        # --- Category path ---
        if categories:
            owasp_dir = self._settings._resolve_owasp_dir()
            for cat in categories:
                cat_clean = cat.replace(" ", "").replace("_", "-").lower()
                candidate = owasp_dir / f"{cat_clean}.yml"
                if candidate.is_file():
                    findings = self._run_single_config(str(candidate), cat)
                    all_findings.extend(findings)

        return all_findings

    def _run_single_config(
        self,
        config_path: str,
        config_name: str,
    ) -> List[Finding]:
        """Run Promptfoo evaluation for a single config file.

        Args:
            config_path: Absolute or relative path to the YAML config.
            config_name: Short name used for finding IDs.

        Returns:
            List of findings from this config.
        """
        for attempt in range(1, self._settings.max_retries + 1):
            try:
                rc, stdout, stderr = self.run_promptfoo_eval(config_path)
                if rc == 0:
                    return self._parse_promptfoo_output(stdout, config_name)
                else:
                    if attempt == self._settings.max_retries:
                        return [
                            Finding(
                                vulnerability=Vulnerability(
                                    id=f"run_error_{config_name}",
                                    name=f"Promptfoo evaluation failed: {config_name}",
                                    type=VulnerabilityType.ADVERSARIAL,
                                    severity=Severity.HIGH,
                                    description=f"Exit code {rc}: {stderr[:200]}",
                                    owasp_category="",
                                    mitigation="Check Promptfoo logs for details",
                                ),
                                test_prompt="",
                                model_response="",
                                is_vulnerable=True,
                                cvss_score=8.0,
                                metadata={"stderr": stderr[:500]},
                            )
                        ]
            except FileNotFoundError:
                return [
                    Finding(
                        vulnerability=Vulnerability(
                            id="promptfoo_missing",
                            name="Promptfoo not installed",
                            type=VulnerabilityType.ADVERSARIAL,
                            severity=Severity.CRITICAL,
                            description=(
                                "Promptfoo is required to run security evaluations"
                            ),
                            owasp_category="",
                            mitigation="Install with: npm install -g promptfoo",
                        ),
                        test_prompt="",
                        model_response="",
                        is_vulnerable=True,
                        cvss_score=10.0,
                    )
                ]
            except subprocess.TimeoutExpired:
                if attempt == self._settings.max_retries:
                    return [
                        Finding(
                            vulnerability=Vulnerability(
                                id=f"timeout_{config_name}",
                                name=f"Scan timeout: {config_name}",
                                type=VulnerabilityType.ADVERSARIAL,
                                severity=Severity.MEDIUM,
                                description="Evaluation exceeded configured timeout",
                                owasp_category="",
                                mitigation="Increase SECURITY_TIMEOUT or check for slow responses",
                            ),
                            test_prompt="",
                            model_response="",
                            is_vulnerable=True,
                            cvss_score=5.0,
                        )
                    ]
        return []

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def list_owasp_configs(self) -> List[str]:
        """Return sorted list of bundled OWASP config basenames (no extension).

        Returns:
            List of names like ``["LLM01-injection", "LLM02-output-filtering", ...]``.
        """
        d = self._settings._resolve_owasp_dir()
        if not d.is_dir():
            return []
        return sorted(
            f.stem for f in d.iterdir() if f.suffix in (".yml", ".yaml")
        )

    def list_quick_start_configs(self) -> List[str]:
        """Return sorted list of quick-start config basenames."""
        d = self._settings._resolve_quick_start_dir()
        if not d.is_dir():
            return []
        return sorted(
            f.stem for f in d.iterdir() if f.suffix in (".yml", ".yaml")
        )
