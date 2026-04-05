# API Reference

Complete Python API reference for the AI Security Framework.

---

## Installation

```bash
pip install ai-security-framework
```

---

## Quick Reference

```python
from ai_security import (
    SecurityScanner,     # Core scan engine
    RedTeam,             # Attack simulation
    ReportGenerator,     # Multi-format reports
    ComplianceAuditor,   # OWASP + NIST audits
    Finding,             # Single scan result
    Severity,            # Severity enum
    Vulnerability,       # Vulnerability definition
    VulnerabilityType,   # Vulnerability categories
    ReportFormat,        # Report format enum
    ComplianceReport,    # Audit report result
    ComplianceFramework, # Framework enum
    Settings,            # Configuration
    __version__,         # Package version
)
```

---

## `SecurityScanner`

Core scan engine. Runs Promptfoo evaluations against OWASP LLM Top 10 configs and returns structured `Finding` objects.

### Constructor

```python
SecurityScanner(target: str = "", settings: Settings | None = None)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `str` | `""` | URL or API endpoint to scan |
| `settings` | `Settings` | `None` | Optional settings override (uses defaults if `None`) |

### Methods

#### `run_scan()`

```python
run_scan(
    config_files: list[str] | None = None,
    categories: list[str] | None = None,
    quick_start: str | None = None,
) -> list[Finding]
```

Execute security scans. One of the three parameters must be provided.

| Parameter | Description |
|-----------|-------------|
| `config_files` | Explicit paths to Promptfoo YAML config files |
| `categories` | OWASP LLM category codes (e.g. `["LLM01", "LLM02"]`) |
| `quick_start` | Quick-start preset name (e.g. `"basic-scan"`) |

**Returns:** `list[Finding]` — structured scan results.

**Raises:**
- `ValueError` — if target is empty and no configs are provided
- `FileNotFoundError` — if a config file doesn't exist

**Example:**

```python
from ai_security import SecurityScanner

scanner = SecurityScanner(target="https://api.example.com/v1/chat")

# Scan specific OWASP categories
findings = scanner.run_scan(categories=["LLM01", "LLM06"])

for f in findings:
    status = "VULNERABLE" if f.is_vulnerable else "PASS"
    print(f"[{f.vulnerability.severity.value}] {f.vulnerability.name} — {status}")
```

#### `run_promptfoo_eval()`

```python
run_promptfoo_eval(
    config_path: str | Path,
    output_path: str | Path | None = None,
) -> tuple[int, str, str]
```

Run `promptfoo eval` directly. Internal method exposed for advanced use.

**Returns:** Tuple of `(return_code, stdout, stderr)`.

#### `list_owasp_configs()`

```python
list_owasp_configs() -> list[str]
```

Return sorted list of bundled OWASP config basenames.

```python
>>> scanner.list_owasp_configs()
['LLM01-injection', 'LLM02-output-filtering', ..., 'LLM10-model-theft']
```

#### `list_quick_start_configs()`

```python
list_quick_start_configs() -> list[str]
```

Return sorted list of quick-start config basenames.

```python
>>> scanner.list_quick_start_configs()
['basic-scan', 'chatbot-scan', 'rag-app-scan']
```

---

## `Finding` — Scan Result

A single result from a security test.

```python
@dataclass
class Finding:
    vulnerability: Vulnerability     # What this finding relates to
    test_prompt: str                 # The prompt sent to the model
    model_response: str              # The raw response text
    is_vulnerable: bool              # True if the model failed the test
    evidence: str                    # Additional evidence / raw output
    cvss_score: float                # Numeric CVSS score (0.0 – 10.0)
    metadata: dict[str, Any]         # Extra data
```

```python
# Check if a finding is a failure
if finding.is_vulnerable:
    print(f"Found {finding.vulnerability.severity.value} issue!")
    print(f"  Category: {finding.vulnerability.owasp_category}")
    print(f"  CVSS: {finding.cvss_score}")
    print(f"  Fix: {finding.vulnerability.mitigation}")

# Serialize
data = finding.to_dict()  # JSON-compatible dict
```

---

## `Severity`

CVSS-style severity levels.

```python
class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
```

```python
from ai_security import Severity

Severity.CRITICAL.sort_key  # → 4
Severity.MEDIUM.sort_key    # → 2
```

---

## `VulnerabilityType`

AI/LLM vulnerability categories.

```python
class VulnerabilityType(str, Enum):
    PROMPT_INJECTION       = "prompt_injection"
    JAILBREAK              = "jailbreak"
    PII_EXPOSURE           = "pii_exposure"
    TOXICITY               = "toxicity"
    DATA_LEAKAGE           = "data_leakage"
    CONTEXT_POISONING      = "context_poisoning"
    SYSTEM_PROMPT_LEAK     = "system_prompt_leak"
    ADVERSARIAL            = "adversarial"
    OVERRELIANCE           = "overreliance"
    EXCESSIVE_AGENCY       = "excessive_agency"
    MODEL_THEFT            = "model_theft"
    SUPPLY_CHAIN           = "supply_chain"
```

---

## `RedTeam`

Attack simulation engine. Wraps `promptfoo redteam` with built-in fallback payloads.

### Constructor

```python
RedTeam(target: str, purpose: str = "", settings: Settings | None = None)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | `str` | ✅ | LLM endpoint URL |
| `purpose` | `str` | No | Human-readable description of the target |
| `settings` | `Settings` | No | Optional settings override |

### Methods

#### `run()`

```python
run(
    plugins: list[str] | None = None,
    strategies: list[str] | None = None,
) -> list[Finding]
```

Execute red-team campaign.

| Parameter | Description |
|-----------|-------------|
| `plugins` | Attack plugins: `"default"`, `"injection"`, `"jailbreak"`, `"toxicity"`, `"pii"` |
| `strategies` | Strategies: `"direct"`, `"indirect"`, `"multi_turn"`, `"encoding"`, `"role_play"`, `"context_injection"` |

**Example:**

```python
from ai_security import RedTeam

rt = RedTeam(target="https://api.example.com/v1/chat")

# All attacks
findings = rt.run()

# Specific plugins and strategies
findings = rt.run(
    plugins=["injection", "jailbreak"],
    strategies=["direct", "multi_turn"]
)

# Summarize
report = rt.generate_report(findings)
print(f"Attacks: {report['summary']['total_tests']}")
print(f"Vulnerable: {report['summary']['vulnerabilities_found']}")
```

#### `generate_report()`

```python
generate_report(findings: list[Finding]) -> dict[str, Any]
```

Produce a summary report.

**Returns:**

```python
{
    "summary": {
        "total_tests": 18,
        "vulnerabilities_found": 5,
        "passed": 13,
        "average_cvss": 6.42
    },
    "by_severity": {
        "critical": 1,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0
    },
    "findings": [...]  # list of finding dicts
}
```

---

## `ReportGenerator`

Multi-format report generator. Produces JSON, HTML, or Markdown.

### Constructor

```python
ReportGenerator(
    title: str = "AI Security Assessment Report",
    include_remediation: bool = True,
)
```

### Methods

#### `generate_json()` / `generate_html()` / `generate_markdown()`

```python
generate_json(findings: list[Finding]) -> str
generate_html(findings: list[Finding]) -> str
generate_markdown(findings: list[Finding]) -> str
```

Return formatted report as a string.

#### `save()`

```python
save(
    findings: list[Finding],
    format: ReportFormat | str = ReportFormat.JSON,
    output_path: str | Path = "report",
) -> str
```

Generate and write report. Returns the output file path.

**Example:**

```python
from ai_security import ReportGenerator, ReportFormat

reporter = ReportGenerator()

# Save in all three formats
reporter.save(findings, "json", "security-report.json")
reporter.save(findings, "html", "security-report.html")
reporter.save(findings, "markdown", "security-report.md")

# Auto-inferred format from extension
reporter.save(findings, "html", "report")  # → report.html
```

#### Convenience Methods

```python
reporter.to_json(findings, "report.json")      # → "report.json"
reporter.to_html(findings, "report.html")      # → "report.html"
reporter.to_markdown(findings, "report.md")    # → "report.md"
```

### Report Content

All reports include:

| Section | Description |
|---------|-------------|
| **Summary** | Total findings, vulnerable count, average CVSS, worst severity |
| **Severity Breakdown** | Count by severity level |
| **Detailed Findings** | Each finding with severity, OWASP category, CVSS, status |
| **Remediation** | Category-specific recommendations (when `include_remediation=True`) |

---

## `ComplianceAuditor`

Audit findings against OWASP LLM Top 10 and NIST AI RMF.

### Constructor

```python
ComplianceAuditor(settings: Settings | None = None)
```

### Methods

#### `audit()`

```python
audit(
    findings: list[Finding],
    framework: str | ComplianceFramework = ComplianceFramework.OWASP,
) -> ComplianceReport
```

Audit findings against a compliance framework.

| Parameter | Description |
|-----------|-------------|
| `findings` | List of `Finding` objects from scanner or redteam |
| `framework` | `"owasp"` or `"nist_ai_rmf"` |

**Returns:** `ComplianceReport` with per-category results.

**Example:**

```python
from ai_security import ComplianceAuditor, ComplianceFramework

auditor = ComplianceAuditor()

# OWASP audit
report = auditor.audit(findings, framework="owasp")
print(f"OWASP Score: {report.score}/100 — {report.overall_status}")

# NIST AI RMF audit
nist = auditor.audit(findings, framework="nist_ai_rmf")
print(f"NIST Score: {nist.score}/100 — {nist.overall_status}")

# Category details
for cat in report.categories:
    print(f"  {cat.category_id} ({cat.name}): {cat.status}")
    if cat.recommendations:
        for rec in cat.recommendations:
            print(f"    → {rec}")
```

#### `load_vulnerability_database()`

```python
load_vulnerability_database() -> dict[str, Any]
```

Load the bundled `vulnerabilities.json` database.

#### `load_attack_patterns()`

```python
load_attack_patterns() -> dict[str, Any]
```

Load the bundled `attack-patterns.yml` attack library.

---

## `ComplianceReport` — Audit Result

```python
@dataclass
class ComplianceReport:
    framework: str           # "OWASP LLM Top 10" or "NIST AI Risk Management Framework"
    framework_version: str   # "2025" or "1.0"
    generated_at: str        # ISO timestamp
    overall_status: str      # "PASS", "FAIL", or "WARN"
    score: float             # 0.0 – 100.0
    passed: int              # Categories passed
    failed: int              # Categories failed
    warned: int              # Categories not tested
    categories: list[ComplianceCategory]
    recommendations: list[str]
```

```python
# Serialize
data = report.to_dict()  # JSON-compatible dict
```

---

## `ComplianceFramework`

```python
class ComplianceFramework(str, Enum):
    OWASP = "owasp"
    NIST_AI_RMF = "nist_ai_rmf"
```

---

## `Settings`

Configuration management with layered overrides.

### Constructor

```python
Settings(
    target: str = "",
    provider: str = "openai:chat:gpt-4o",
    promptfoo_path: str | None = None,
    timeout_sec: int = 600,
    max_retries: int = 3,
    report_output_dir: str = "./security-results",
    report_formats: list[str] | None = None,  # ["json", "html"]
    owasp_config_dir: str = "",
    quick_start_config_dir: str = "",
    data_dir: str = "",
)
```

### Factory Methods

```python
# From environment variables (SECURITY_*)
settings = Settings.from_env()

# From YAML file
settings = Settings.from_yaml("security-config.yml")
```

### Environment Variables

| Variable | Setting | Default |
|----------|---------|---------|
| `SECURITY_TARGET` | `target` | `""` |
| `SECURITY_PROVIDER` | `provider` | `"openai:chat:gpt-4o"` |
| `SECURITY_PROMPTFOO_PATH` | `promptfoo_path` | `None` |
| `SECURITY_TIMEOUT` | `timeout_sec` | `600` |
| `SECURITY_MAX_RETRIES` | `max_retries` | `3` |
| `SECURITY_REPORT_DIR` | `report_output_dir` | `"./security-results"` |

---

## Complete Workflow Example

```python
from ai_security import SecurityScanner, RedTeam, ReportGenerator, ComplianceAuditor

TARGET = "https://api.example.com/v1/chat"

# --- Phase 1: Scan ---
scanner = SecurityScanner(target=TARGET)
findings = scanner.run_scan(categories=["LLM01", "LLM06", "LSM08"])

# --- Phase 2: Red Team ---
rt = RedTeam(target=TARGET, purpose="Production customer support chatbot")
rt_findings = rt.run(plugins=["injection", "jailbreak"])
all_findings = findings + rt_findings

# --- Phase 3: Reports ---
reporter = ReportGenerator(title="Q2 Security Assessment")
reporter.to_html(all_findings, "reports/q2-security.html")
reporter.to_markdown(all_findings, "reports/q2-security.md")

# --- Phase 4: Compliance ---
auditor = ComplianceAuditor()

owasp = auditor.audit(all_findings, framework="owasp")
print(f"OWASP Compliance: {owasp.score}/100 ({owasp.overall_status})")

nist = auditor.audit(all_findings, framework="nist_ai_rmf")
print(f"NIST AI RMF: {nist.score}/100 ({nist.overall_status})")
```

---

*For CLI usage, see [CLI.md](CLI.md). For architecture, see [ARCHITECTURE.md](ARCHITECTURE.md).*
