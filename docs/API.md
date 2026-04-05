# API.md — Python API Reference

## Installation

```bash
pip install ai-security-framework
```

## Quick Start

```python
from ai_security import SecurityScanner, ComplianceAuditor, ReportGenerator

# 1. Scan a target
scanner = SecurityScanner(target="https://api.example.com/v1/chat")
findings = scanner.run_scan(quick_start="basic-scan")

# 2. Generate reports
reporter = ReportGenerator()
reporter.to_json(findings, "report.json")
reporter.to_html(findings, "report.html")
reporter.to_markdown(findings, "report.md")

# 3. Run compliance audit
auditor = ComplianceAuditor()
owasp_report = auditor.audit(findings, framework="owasp")
print(f"OWASP Score: {owasp_report.score}/100")
```

---

## `SecurityScanner`

```python
from ai_security import SecurityScanner
from ai_security.config import Settings
```

### Constructor

```python
SecurityScanner(
    target: str = "",          # LLM endpoint URL
    settings: Settings | None  # Optional settings override
)
```

### Methods

#### `run_scan()`

Execute security scans.

```python
findings = scanner.run_scan(
    config_files=["LLM01-injection.yml"],  # explicit config paths
    categories=["LLM01", "LLM02"],          # bundled OWASP categories
    quick_start="basic-scan",               # quick-start config name
)
```

**Returns:** `list[Finding]`

#### `list_owasp_configs()`

List bundled OWASP config names.

#### `list_quick_start_configs()`

List bundled quick-start config names.

---

## `RedTeam`

```python
from ai_security import RedTeam
```

### Constructor

```python
RedTeam(
    target: str,       # Required: LLM endpoint
    purpose: str = "",  # Description of target
    settings: Settings | None = None,
)
```

### Methods

#### `run()`

Execute red-team attack campaign.

```python
findings = rt.run(
    plugins=["default", "jailbreak"],  # attack plugins
    strategies=["direct", "multi_turn"], # attack strategies
)
```

#### `generate_report()`

Produce summary report dict.

```python
report = rt.generate_report(findings)
print(report["summary"]["vulnerabilities_found"])
```

---

## `ReportGenerator`

```python
from ai_security import ReportGenerator, ReportFormat
```

### Constructor

```python
ReportGenerator(
    title: str = "AI Security Assessment Report",
    include_remediation: bool = True,
)
```

### Methods

#### `generate_json(findings)` → `str`

Returns JSON string.

#### `generate_html(findings)` → `str`

Returns complete HTML document with severity colours.

#### `generate_markdown(findings)` → `str`

Returns Markdown string suitable for GitHub issues.

#### `save(findings, format, output_path)` → `str`

Generate and save report. Returns absolute path.

```python
path = reporter.save(findings, "html", "report.html")
```

#### Convenience methods

```python
reporter.to_json(findings, "report.json")
reporter.to_html(findings, "report.html")
reporter.to_markdown(findings, "report.md")
```

---

## `ComplianceAuditor`

```python
from ai_security import ComplianceAuditor
```

### Constructor

```python
ComplianceAuditor(settings: Settings | None = None)
```

### Methods

#### `audit(findings, framework)` → `ComplianceReport`

```python
report = auditor.audit(findings, framework="owasp")      # or "nist_ai_rmf"
print(report.overall_status)  # "PASS" | "FAIL" | "WARN"
print(report.score)           # 0.0 – 100.0
```

#### `load_vulnerability_database()` → `dict`

Load bundled vulnerabilities.json.

#### `load_attack_patterns()` → `dict`

Load bundled attack-patterns.yml.

---

## `Settings`

```python
from ai_security.config import Settings
```

### Factory methods

```python
# From environment variables
settings = Settings.from_env()

# From YAML file
settings = Settings.from_yaml("my-config.yml")
```

### Attributes

| Attribute | Default | Description |
|-----------|---------|-------------|
| `target` | `""` | Target URL |
| `provider` | `"openai:chat:gpt-4o"` | Model provider string |
| `promptfoo_path` | `None` | Custom promptfoo binary path |
| `timeout_sec` | `600` | Evaluation timeout |
| `max_retries` | `3` | Retry count |
| `report_output_dir` | `"./security-results"` | Default output directory |

---

## Data Types

### `Finding`

```python
from ai_security import Finding
```

| Attribute | Type | Description |
|-----------|------|-------------|
| `vulnerability` | `Vulnerability` | Associated vulnerability |
| `test_prompt` | `str` | Prompt sent to model |
| `model_response` | `str` | Model's response |
| `is_vulnerable` | `bool` | True if test failed |
| `evidence` | `str` | Additional evidence |
| `cvss_score` | `float` | 0.0 – 10.0 |
| `metadata` | `dict` | Extra data |

### `Severity` enum

`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

### `VulnerabilityType` enum

`PROMPT_INJECTION`, `JAILBREAK`, `PII_EXPOSURE`, `TOXICITY`, `DATA_LEAKAGE`,
`CONTEXT_POISONING`, `SYSTEM_PROMPT_LEAK`, `ADVERSARIAL`, `OVERRELIANCE`,
`EXCESSIVE_AGENCY`, `MODEL_THEFT`, `SUPPLY_CHAIN`

### `ComplianceFramework` enum

`OWASP`, `NIST_AI_RMF`

### `ReportFormat` enum

`JSON`, `HTML`, `MARKDOWN`
