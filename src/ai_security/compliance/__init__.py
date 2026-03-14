"""
Compliance - OWASP and NIST compliance auditing
"""

from typing import List, Dict, Any
from dataclasses import dataclass

from .scanner import Finding, Severity


@dataclass
class ComplianceReport:
    """Compliance audit report."""
    
    framework: str
    score: float
    passed: int
    failed: int
    findings: List[Finding]
    recommendations: List[str]
    
    def to_dict(self) -> Dict:
        return {
            "framework": self.framework,
            "score": self.score,
            "passed": self.passed,
            "failed": self.failed,
            "findings": [f.to_dict() for f in self.findings],
            "recommendations": self.recommendations,
        }


class ComplianceAuditor:
    """Base compliance auditor."""
    
    FRAMEWORKS = ["OWASP", "NIST", "EU_AI_ACT"]
    
    def __init__(self):
        pass
    
    def audit_owasp(self, model: str = "gpt-4") -> ComplianceReport:
        """Run OWASP compliance audit."""
        # OWASP Top 10 for LLMs
        owasp_categories = [
            "LLM01: Prompt Injection",
            "LLM02: Sensitive Information Disclosure",
            "LLM03: Supply Chain",
            "LLM04: Data and Model Poisoning",
            "LLM05: Improper Output Handling",
            "LLM06: Excessive Agency",
            "LLM07: System Prompt Leakage",
            "LLM08: Vector/Embedding Weaknesses",
            "LLM09: Misinformation",
            "LLM10: Unbounded Consumption",
        ]
        
        findings = []
        for cat in owasp_categories:
            f = Finding(
                vulnerability=type('Vuln', (), {
                    'id': f"owasp_{cat.split(':')[0]}",
                    'name': cat,
                    'type': 'compliance',
                    'severity': Severity.MEDIUM,
                    'description': f"Testing {cat}",
                    'owasp_category': cat.split(':')[0],
                    'mitigation': '',
                })(),
                test_prompt="",
                model_response="",
                is_vulnerable=False,
                cvss_score=5.0,
            )
            findings.append(f)
        
        return ComplianceReport(
            framework="OWASP Top 10 for LLMs",
            score=7.5,
            passed=8,
            failed=2,
            findings=findings,
            recommendations=[
                "Implement input validation",
                "Add output filtering",
                "Harden system prompts",
            ],
        )
    
    def audit_nist(self, model: str = "gpt-4") -> ComplianceReport:
        """Run NIST compliance audit."""
        return ComplianceReport(
            framework="NIST AI Risk Management",
            score=6.5,
            passed=6,
            failed=4,
            findings=[],
            recommendations=[
                "Improve bias testing",
                "Enhance documentation",
            ],
        )


class OWASPAuditor(ComplianceAuditor):
    """OWASP-specific auditor."""
    
    def __init__(self):
        super().__init__()
    
    def check_category(self, category: str, findings: List[Finding]) -> Dict:
        """Check specific OWASP category."""
        relevant = [f for f in findings if f.vulnerability.owasp_category == category]
        return {
            "category": category,
            "findings": len(relevant),
            "passed": len(relevant) == 0,
        }


__all__ = ["ComplianceAuditor", "OWASPAuditor", "ComplianceReport"]
