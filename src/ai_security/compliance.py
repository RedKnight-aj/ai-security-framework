"""
Compliance Auditor — OWASP LLM Top 10 & NIST AI RMF compliance auditing.

The :class:`ComplianceAuditor` class evaluates :class:`Finding` objects
against compliance frameworks, producing structured
:class:`ComplianceReport` objects with PASS/FAIL per category, risk
scores, and category-specific remediation recommendations.

Usage::

    from ai_security import ComplianceAuditor, SecurityScanner

    scanner = SecurityScanner(target="https://api.example.com")
    findings = scanner.run_scan(categories=["LLM01", "LLM02"])

    auditor = ComplianceAuditor()
    report = auditor.audit(findings, framework="owasp")
    print(report.to_dict())
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

from .scanner import Finding, Severity, Vulnerability
from .config import Settings

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""

    OWASP = "owasp"
    NIST_AI_RMF = "nist_ai_rmf"


# ---------------------------------------------------------------------------
# Framework metadata
# ---------------------------------------------------------------------------

_OWASP_CATEGORIES: Dict[str, Dict[str, str]] = {
    "LLM01": {
        "name": "Prompt Injection",
        "severity": "CRITICAL",
        "description": "Crafted inputs manipulate LLM behavior by overriding system instructions.",
    },
    "LLM02": {
        "name": "Insecure Output Handling",
        "severity": "HIGH",
        "description": "LLM output is handled without sufficient scrutiny, leading to XSS, CSRF, SSRF, or RCE.",
    },
    "LLM03": {
        "name": "Training Data Poisoning",
        "severity": "HIGH",
        "description": "Manipulation of training data introduces vulnerabilities, biases, or backdoors.",
    },
    "LLM04": {
        "name": "Model Denial of Service",
        "severity": "MEDIUM",
        "description": "Resource-intensive inputs lead to degraded performance or disproportionate costs.",
    },
    "LLM05": {
        "name": "Supply Chain Vulnerabilities",
        "severity": "HIGH",
        "description": "Components, datasets, or models in the development lifecycle lead to unexpected results.",
    },
    "LLM06": {
        "name": "Sensitive Information Disclosure",
        "severity": "CRITICAL",
        "description": "Confidential data, IP, or privacy violations exposed through model interactions.",
    },
    "LLM07": {
        "name": "Insecure Plugin Design",
        "severity": "HIGH",
        "description": "Plugins with insufficient input validation and excessive privileges.",
    },
    "LLM08": {
        "name": "Excessive Agency",
        "severity": "HIGH",
        "description": "Autonomous actions beyond intended scope cause unintended consequences.",
    },
    "LLM09": {
        "name": "Overreliance",
        "severity": "MEDIUM",
        "description": "Over-reliance on LLM outputs leads to misinformation or security decisions without human oversight.",
    },
    "LLM10": {
        "name": "Model Theft",
        "severity": "HIGH",
        "description": "Unauthorized access to proprietary models through theft, replication, or data extraction.",
    },
}

_NIST_AI_RMF_CATEGORIES: Dict[str, Dict[str, str]] = {
    "GOVERN": {
        "name": "Govern",
        "description": (
            "Organization has policies, processes, and procedures for trustworthy AI."
        ),
    },
    "MAP": {
        "name": "Map",
        "description": (
            "Context for AI system capabilities, risks, and impacts is measured and tracked."
        ),
    },
    "MEASURE": {
        "name": "Measure",
        "description": (
            "AI system performance is assessed with appropriate metrics and testing."
        ),
    },
    "MANAGE": {
        "name": "Manage",
        "description": "AI risks are tracked, mitigated, and continuously monitored.",
    },
}

# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------


@dataclass
class ComplianceCategory:
    """Single category result within a compliance audit."""

    category_id: str
    name: str
    status: str  # "PASS", "FAIL", or "WARN"
    severity: str
    findings: List[Finding] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "category_id": self.category_id,
            "name": self.name,
            "status": self.status,
            "severity": self.severity,
            "finding_count": len(self.findings),
            "recommendations": self.recommendations,
        }


@dataclass
class ComplianceReport:
    """Complete compliance audit report."""

    framework: str
    framework_version: str
    generated_at: str
    overall_status: str  # "PASS", "FAIL", or "WARN"
    score: float  # 0.0 – 100.0
    passed: int
    failed: int
    warned: int
    categories: List[ComplianceCategory]
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "framework": self.framework,
            "framework_version": self.framework_version,
            "generated_at": self.generated_at,
            "overall_status": self.overall_status,
            "score": self.score,
            "passed": self.passed,
            "failed": self.failed,
            "warned": self.warned,
            "categories": [c.to_dict() for c in self.categories],
            "recommendations": self.recommendations,
        }


# ---------------------------------------------------------------------------
# Remediation recommendations per OWASP category
# ---------------------------------------------------------------------------

_OASP_RECOMMENDATIONS: Dict[str, List[str]] = {
    "LLM01": [
        "Implement structural separation between system prompts and user input.",
        "Treat all external content (RAG, APIs, web) as untrusted data.",
        "Deploy input sanitization and output validation layers.",
        "Use parameterized prompt templates — never concatenate user input into system prompts.",
        "Consider deploying a secondary LLM guard classifier.",
    ],
    "LLM02": [
        "Add output encoding and escaping for all generated content.",
        "Implement Content-Security-Policy for web-facing endpoints.",
        "Never insert LLM output directly into HTML, SQL, or shell commands.",
        "Validate all generated code before execution.",
        "Implement safe code generation templates.",
    ],
    "LLM03": [
        "Implement data provenance verification and integrity checks.",
        "Use differential privacy during training.",
        "Apply robust fine-tuning (RLHF, DPO).",
        "Maintain clean baseline models for comparison.",
    ],
    "LLM04": [
        "Implement strict input length limits (character/token caps).",
        "Deploy rate limiting and abuse detection.",
        "Set generation timeouts and recursion limits.",
    ],
    "LLM05": [
        "Verify model provenance with signatures and checksums.",
        "Use trusted model registries only.",
        "Implement SBOM validation for all dependencies.",
    ],
    "LLM06": [
        "Isolate credentials from model access.",
        "Implement comprehensive secret scanning in outputs.",
        "Use credential managers with automatic rotation.",
    ],
    "LLM07": [
        "Implement parameter validation for all tool calls.",
        "Sandbox tool execution environments.",
        "Require human approval for high-risk tool calls.",
        "Apply principle of least privilege for tool permissions.",
    ],
    "LLM08": [
        "Define and enforce strict agent permission boundaries.",
        "Implement human approval for critical actions.",
        "Deploy agent activity monitoring and audit trails.",
    ],
    "LLM09": [
        "Implement fact-checking against verified sources.",
        "Add confidence indicators to all responses.",
        "Require source attribution for factual claims.",
    ],
    "LLM10": [
        "Implement API rate limiting and query pattern monitoring.",
        "Add model watermarks and fingerprinting.",
        "Deploy detection for distillation attacks.",
    ],
}

# ---------------------------------------------------------------------------
# NIST AI RMF recommendations
# ---------------------------------------------------------------------------

_NIST_RECOMMENDATIONS: Dict[str, List[str]] = {
    "GOVERN": [
        "Establish an AI governance policy aligned with organizational risk tolerance.",
        "Define roles and responsibilities for AI system oversight.",
        "Conduct regular AI risk management training for all stakeholders.",
        "Implement continuous monitoring of AI system compliance.",
    ],
    "MAP": [
        "Document all AI system capabilities and limitations.",
        "Map data flows and external dependencies for each AI system.",
        "Identify potential impacts on individuals, communities, and organizations.",
        "Maintain an inventory of all AI systems in production.",
    ],
    "MEASURE": [
        "Establish quantitative metrics for AI system performance and safety.",
        "Conduct regular adversarial testing and red-teaming exercises.",
        "Benchmark AI outputs against trusted reference datasets.",
        "Measure and track bias, fairness, and accuracy metrics over time.",
    ],
    "MANAGE": [
        "Maintain a risk register for all AI systems.",
        "Develop and test incident response plans for AI failures.",
        "Implement feedback loops for continuous risk reduction.",
        "Provide clear mechanisms for users to report AI-related issues.",
    ],
}


# ---------------------------------------------------------------------------
# ComplianceAuditor
# ---------------------------------------------------------------------------


class ComplianceAuditor:
    """Audit AI security findings against OWASP and NIST compliance frameworks.

    Usage::

        auditor = ComplianceAuditor()
        report = auditor.audit(findings, framework="owasp")
        print(report.score)          # 0-100 score
        print(report.overall_status) # PASS / FAIL / WARN
    """

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self._settings = settings or Settings()

    # ------------------------------------------------------------------
    # Data loaders
    # ------------------------------------------------------------------

    def load_vulnerability_database(self) -> Dict[str, Any]:
        """Load the bundled vulnerabilities.json database.

        Returns:
            Parsed JSON dictionary.

        Raises:
            FileNotFoundError: If the database file is not found.
        """
        db_path = self._settings._resolve_data_dir() / "vulnerabilities.json"
        if not db_path.exists():
            raise FileNotFoundError(f"Vulnerability database not found: {db_path}")
        with db_path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    def load_attack_patterns(self) -> Dict[str, Any]:
        """Load the bundled attack-patterns.yml library.

        Returns:
            Parsed YAML dictionary.

        Raises:
            FileNotFoundError: If the patterns file is not found.
            ImportError: If PyYAML is not installed.
        """
        ap_path = self._settings._resolve_data_dir() / "attack-patterns.yml"
        if not ap_path.exists():
            raise FileNotFoundError(f"Attack patterns file not found: {ap_path}")
        if yaml is None:
            raise ImportError("PyYAML is required. Install with: pip install pyyaml")
        with ap_path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)

    # ------------------------------------------------------------------
    # Public audit API
    # ------------------------------------------------------------------

    def audit(
        self,
        findings: List[Finding],
        framework: str | ComplianceFramework = ComplianceFramework.OWASP,
    ) -> ComplianceReport:
        """Audit findings against a compliance framework.

        Args:
            findings: List of security findings to audit.
            framework: Framework to audit against (``"owasp"`` or
                       ``"nist_ai_rmf"``).

        Returns:
            A :class:`ComplianceReport` with per-category results.

        Raises:
            ValueError: If the framework is not supported.
        """
        fw = self._resolve_framework(framework)
        if fw == ComplianceFramework.OWASP:
            return self._audit_owasp(findings)
        if fw == ComplianceFramework.NIST_AI_RMF:
            return self._audit_nist(findings)
        raise ValueError(f"Unsupported framework: {fw!r}")

    # ------------------------------------------------------------------
    # OWASP audit
    # ------------------------------------------------------------------

    def _audit_owasp(self, findings: List[Finding]) -> ComplianceReport:
        """Evaluate findings against OWASP LLM Top 10."""
        categories: List[ComplianceCategory] = []
        total_checks = 0
        passed = 0
        failed = 0
        warned = 0

        for cat_id, meta in _OWASP_CATEGORIES.items():
            cat_findings = [
                f for f in findings if f.vulnerability.owasp_category == cat_id
            ]
            is_vulnerable = any(f.is_vulnerable for f in cat_findings)
            total_checks += 1

            if is_vulnerable:
                status = "FAIL"
                failed += 1
            elif cat_findings:
                status = "PASS"
                passed += 1
            else:
                status = "WARN"
                warned += 1

            recs: List[str] = []
            if status == "FAIL":
                recs = _OASP_RECOMMENDATIONS.get(cat_id, [])

            categories.append(
                ComplianceCategory(
                    category_id=cat_id,
                    name=meta["name"],
                    status=status,
                    severity=meta["severity"],
                    findings=cat_findings,
                    recommendations=recs,
                )
            )

        # Score: 100 = fully compliant
        score = (passed / total_checks * 100) if total_checks else 0.0
        overall = "FAIL" if failed > 0 else ("WARN" if warned > 0 else "PASS")

        flat_recs: List[str] = []
        for c in categories:
            flat_recs.extend(c.recommendations)

        return ComplianceReport(
            framework="OWASP LLM Top 10",
            framework_version="2025",
            generated_at=datetime.now(timezone.utc).isoformat(),
            overall_status=overall,
            score=round(score, 1),
            passed=passed,
            failed=failed,
            warned=warned,
            categories=categories,
            recommendations=flat_recs,
        )

    # ------------------------------------------------------------------
    # NIST AI RMF audit
    # ------------------------------------------------------------------

    def _audit_nist(self, findings: List[Finding]) -> ComplianceReport:
        """Evaluate findings against NIST AI Risk Management Framework."""
        # Map OWASP categories to NIST functions
        category_map: Dict[str, Dict[str, str]] = {
            "LLM01": {"nist": "MEASURE", "weight": 3},
            "LLM02": {"nist": "MANAGE", "weight": 2},
            "LLM03": {"nist": "GOVERN", "weight": 2},
            "LLM04": {"nist": "MANAGE", "weight": 2},
            "LLM05": {"nist": "GOVERN", "weight": 2},
            "LLM06": {"nist": "MANAGE", "weight": 3},
            "LLM07": {"nist": "MEASURE", "weight": 2},
            "LLM08": {"nist": "MAP", "weight": 2},
            "LLM09": {"nist": "MAP", "weight": 2},
            "LLM10": {"nist": "MEASURE", "weight": 2},
        }

        nist_findings: Dict[str, List[Finding]] = {
            func: [] for func in _NIST_AI_RMF_CATEGORIES
        }
        for f in findings:
            cat = f.vulnerability.owasp_category
            mapping = category_map.get(cat, {})
            nist_func = mapping.get("nist", "MEASURE")
            nist_findings.setdefault(nist_func, []).append(f)

        categories: List[ComplianceCategory] = []
        total_weight = 0
        weighted_score = 0.0

        for func_id, meta in _NIST_AI_RMF_CATEGORIES.items():
            func_findings = nist_findings.get(func_id, [])
            is_vulnerable = any(f.is_vulnerable for f in func_findings)
            weight = max(
                m["weight"] for m in category_map.values() if m["nist"] == func_id
            )
            total_weight += weight

            if is_vulnerable:
                status = "FAIL"
            elif func_findings:
                status = "PASS"
                weighted_score += weight * 100
            else:
                status = "WARN"
                weighted_score += weight * 50  # partial credit

            recs: List[str] = []
            if status == "FAIL":
                recs = _NIST_RECOMMENDATIONS.get(func_id, [])

            categories.append(
                ComplianceCategory(
                    category_id=func_id,
                    name=meta["name"],
                    status=status,
                    severity="HIGH" if status == "FAIL" else "MEDIUM",
                    findings=func_findings,
                    recommendations=recs,
                )
            )

        score = (
            (weighted_score / total_weight * 100) if total_weight else 0.0
        )
        score = min(score, 100.0)

        passed = sum(1 for c in categories if c.status == "PASS")
        failed = sum(1 for c in categories if c.status == "FAIL")
        warned = sum(1 for c in categories if c.status == "WARN")
        overall = "FAIL" if failed > 0 else ("WARN" if warned > 0 else "PASS")

        flat_recs: List[str] = []
        for c in categories:
            flat_recs.extend(c.recommendations)

        return ComplianceReport(
            framework="NIST AI Risk Management Framework",
            framework_version="1.0",
            generated_at=datetime.now(timezone.utc).isoformat(),
            overall_status=overall,
            score=round(score, 1),
            passed=passed,
            failed=failed,
            warned=warned,
            categories=categories,
            recommendations=flat_recs,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_framework(fw: str | ComplianceFramework) -> ComplianceFramework:
        """Normalise a framework string to a :class:`ComplianceFramework`."""
        if isinstance(fw, ComplianceFramework):
            return fw
        normalised = fw.replace(" ", "_").replace("-", "_").lower()
        try:
            return ComplianceFramework(normalised)
        except ValueError:
            raise ValueError(
                f"Unknown framework: {fw!r}. "
                f"Expected one of: {', '.join(f.value for f in ComplianceFramework)}"
            )
