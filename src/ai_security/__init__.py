"""
AI Security Framework
Production-ready security testing using Promptfoo
"""

from .scanner import SecurityScanner, Vulnerability, Finding
from .redteam import RedTeam, AttackResult
from .reporters import JSONReporter, HTMLReporter, CVSSReporter
from .compliance import ComplianceAuditor, OWASPAuditor
from .config import Settings

__version__ = "1.0.0"

__all__ = [
    "SecurityScanner",
    "Vulnerability",
    "Finding",
    "RedTeam",
    "AttackResult",
    "JSONReporter",
    "HTMLReporter",
    "CVSSReporter",
    "ComplianceAuditor",
    "OWASPAuditor",
    "Settings",
]
