"""
Reporters - Generate security reports
"""

import json
from typing import List, Dict, Any
from pathlib import Path
from abc import ABC, abstractmethod

from .scanner import Finding


class BaseReporter(ABC):
    """Base reporter interface."""
    
    @abstractmethod
    def generate(self, findings: List[Finding]) -> str:
        """Generate report."""
        pass
    
    @abstractmethod
    def save(self, findings: List[Finding], path: str):
        """Save report."""
        pass


class JSONReporter(BaseReporter):
    """Generate JSON reports."""
    
    def generate(self, findings: List[Finding]) -> str:
        """Generate JSON report."""
        data = {
            "summary": {
                "total_findings": len(findings),
                "vulnerable": sum(1 for f in findings if f.is_vulnerable),
            },
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(data, indent=2)
    
    def save(self, findings: List[Finding], path: str):
        """Save JSON report."""
        content = self.generate(findings)
        Path(path).write_text(content)
        print(f"JSON report saved: {path}")


class HTMLReporter(BaseReporter):
    """Generate HTML reports."""
    
    def generate(self, findings: List[Finding]) -> str:
        """Generate HTML report."""
        total = len(findings)
        vulnerable = sum(1 for f in findings if f.is_vulnerable)
        
        # Group by severity
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            by_severity[f.vulnerability.severity.value] = by_severity.get(f.vulnerability.severity.value, 0) + 1
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>AI Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 8px; }}
        .critical {{ color: #8B0000; font-weight: bold; }}
        .high {{ color: #FF4500; }}
        .medium {{ color: #FFA500; }}
        .low {{ color: #FFD700; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #dc3545; color: white; }}
    </style>
</head>
<body>
    <h1>🛡️ AI Security Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Findings: <strong>{total}</strong></p>
        <p>Vulnerable: <strong>{vulnerable}</strong></p>
        <p>By Severity:</p>
        <ul>
            <li class="critical">Critical: {by_severity['CRITICAL']}</li>
            <li class="high">High: {by_severity['HIGH']}</li>
            <li class="medium">Medium: {by_severity['MEDIUM']}</li>
            <li class="low">Low: {by_severity['LOW']}</li>
        </ul>
    </div>
    <table>
        <tr>
            <th>Severity</th>
            <th>Vulnerability</th>
            <th>Type</th>
            <th>OWASP</th>
            <th>CVSS</th>
        </tr>
"""
        for f in findings:
            severity_class = f.vulnerability.severity.value.lower()
            html += f"""        <tr>
            <td class="{severity_class}">{f.vulnerability.severity.value}</td>
            <td>{f.vulnerability.name}</td>
            <td>{f.vulnerability.type.value}</td>
            <td>{f.vulnerability.owasp_category}</td>
            <td>{f.cvss_score:.1f}</td>
        </tr>
"""
        
        html += """    </table>
</body>
</html>"""
        return html
    
    def save(self, findings: List[Finding], path: str):
        """Save HTML report."""
        content = self.generate(findings)
        Path(path).write_text(content)
        print(f"HTML report saved: {path}")


class CVSSReporter(BaseReporter):
    """Generate CVSS-style reports."""
    
    def generate(self, findings: List[Finding]) -> Dict:
        """Generate CVSS report."""
        cvss_scores = [f.cvss_score for f in findings if f.cvss_score > 0]
        
        if not cvss_scores:
            return {"score": 0, "severity": "NONE", "findings": []}
        
        avg_score = sum(cvss_scores) / len(cvss_scores)
        
        if avg_score >= 9.0:
            severity = "CRITICAL"
        elif avg_score >= 7.0:
            severity = "HIGH"
        elif avg_score >= 4.0:
            severity = "MEDIUM"
        elif avg_score >= 0.1:
            severity = "LOW"
        else:
            severity = "NONE"
        
        return {
            "score": round(avg_score, 1),
            "severity": severity,
            "total_findings": len(findings),
            "vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "findings": [f.to_dict() for f in findings],
        }
    
    def save(self, findings: List[Finding], path: str):
        """Save CVSS report."""
        content = json.dumps(self.generate(findings), indent=2)
        Path(path).write_text(content)
        print(f"CVSS report saved: {path}")


__all__ = ["BaseReporter", "JSONReporter", "HTMLReporter", "CVSSReporter"]
