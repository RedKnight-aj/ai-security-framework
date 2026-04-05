# Architecture

How the AI Security Framework works from scan to report.

---

## Overview

The framework is a **Python package** (`ai_security`) that wraps the [Promptfoo](https://github.com/promptfoo/promptfoo) LLM evaluation engine with structured configuration, result parsing, reporting, and compliance auditing layers.

```
┌──────────────────────────────────────────────────────────────────┐
│                        ai-sec-scan CLI                           │
│                     scan │ redteam │ report │ compliance          │
└─────────────────────────────┬────────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
   ┌─────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐
   │Security    │     │   RedTeam   │     │   CLI       │
   │Scanner     │     │             │     │   Helpers   │
   │            │     │             │     │   (Rich)    │
   └─────┬──────┘     └──────┬──────┘     └─────────────┘
         │                   │
   ┌─────▼───────────────────▼──────┐
   │        Promptfoo CLI            │
   │   promptfoo eval  │  redteam    │
   └────────────┬────────────────────┘
                │
   ┌────────────▼────────────────────┐
   │   Target LLM / API Endpoint     │
   │   (OpenAI, Anthropic,           │
   │    Ollama, any HTTP endpoint)   │
   └─────────────────────────────────┘

   ┌─────────────────────────────────┐
   │   ReportGenerator ◄─────────────┤
   │   JSON │ HTML │ Markdown         │
   └─────────────────────────────────┘

   ┌─────────────────────────────────┐
   │   ComplianceAuditor ◄───────────┤
   │   OWASP LLM Top 10              │
   │   NIST AI RMF                   │
   └─────────────────────────────────┘
```

---

## Data Flow: Scan → Report

The typical scan path:

```
1. CLI parses args
        │
2. SecurityScanner(target="…")
        │
3. load OWASP YAML configs (configs/owasp/*.yml)
        │
4. for each config:
     promptfoo eval -c <config>
        │  sub-process call
        ▼
5. Parse JSON output from Promptfoo
        │
6. Build Finding objects (dataclasses)
        │
7. Return List[Finding]
        │
   ┌────┴────┐
   ▼         ▼
Report     Compliance
Gen        Audit
   │         │
   ▼         ▼
JSON/      OWASP/
HTML/      NIST
Markdown   Report
```

---

## Core Components

### 1. `SecurityScanner` (`scanner.py`)

The main scan engine. Drives Promptfoo evaluations against OWASP LLM Top 10 configs.

```
SecurityScanner
├── __init__(target, settings)
├── run_scan(config_files, categories, quick_start)  ← main entry
├── run_promptfoo_eval(config_path, output_path)     ← subprocess
├── _parse_promptfoo_output(stdout, config_name)     ← JSON → Findings
├── _run_single_config(config_path, config_name)     ← retry loop
├── list_owasp_configs()                             ← utility
└── list_quick_start_configs()                       ← utility

Data Types:
├── Finding      ← single test result
├── Vulnerability ← vulnerability definition
├── Severity     ← INFO/LOW/MEDIUM/HIGH/CRITICAL
└── VulnerabilityType  ← 12 vulnerability categories
```

**Key design decisions:**
- Promptfoo is invoked as a subprocess (`promptfoo eval`), not imported as a library
- Retries with configurable max (default 3) on transient failures
- Graceful fallback: if promptfoo is missing, returns a finding that says so
- Output parsing handles multiple Promptfoo JSON structures

### 2. `RedTeam` (`redteam.py`)

Red-team attack simulation engine. Wraps `promptfoo redteam` with built-in fallback payloads.

```
RedTeam
├── __init__(target, purpose, settings)
├── run(plugins, strategies)  ← main entry
├── generate_report(findings) ← summary dict
├── _run_promptfoo_redteam(strategy)  ← subprocess
│
Fallback Payloads (when promptfoo unavailable):
├── _attack_injection(strategies)
├── _attack_jailbreak(strategies)
├── _attack_toxicity()
└── _attack_pii()

Enums:
├── AttackStrategy  ← direct, indirect, multi_turn, encoding, role_play, context_injection
└── AttackPlugin    ← default, jailbreak, injection, toxicity, pii
```

### 3. `ReportGenerator` (`reporter.py`)

Multi-format report generator. Consumes `List[Finding]`, produces JSON/HTML/Markdown.

```
ReportGenerator
├── __init__(title, include_remediation)
├── generate_json(findings)   ← string
├── generate_html(findings)   ← string with inline CSS
├── generate_markdown(findings)  ← string
│
Convenience:
├── to_json(findings, path)        ← save JSON
├── to_html(findings, path)        ← save HTML
├── to_markdown(findings, path)    ← save Markdown
└── save(findings, format, path)   ← generic save
│
Internal:
├── _build_report_dict(findings)   ← canonical dict
├── _build_html(findings)          ← HTML builder
├── _build_markdown(findings)      ← Markdown builder
└── _build_remediation(findings)   ← category-level fixes
```

The HTML reporter builds a complete, styled document with severity-coloured badges, summary cards, findings table, and remediation cards.

### 4. `ComplianceAuditor` (`compliance.py`)

Audits findings against compliance frameworks.

```
ComplianceAuditor
├── __init__(settings)
├── audit(findings, framework)  ← main entry
├── _audit_owasp(findings)      ← OWASP LLM Top 10
├── _audit_nist(findings)       ← NIST AI RMF (4 functions)
├── load_vulnerability_database()  ← vulnerabilities.json
└── load_attack_patterns()      ← attack-patterns.yml

Data Types:
├── ComplianceReport   ← full audit report
└── ComplianceCategory ← per-category result
```

**NIST AI RMF mapping:** OWASP categories are weighted and mapped to the four NIST functions (GOVERN, MAP, MEASURE, MANAGE).

### 5. `Settings` (`config.py`)

Configuration management with layered overrides.

```
Settings  (dataclass)
├── from_env()         ← SECURITY_* env vars
├── from_yaml(path)    ← YAML file
├── to_dict()          ← plain dict
├── _resolve_owasp_dir()       ← configs/owasp/
├── _resolve_quick_start_dir() ← configs/quick-start/
└── _resolve_data_dir()        ← data/
```

Priority: constructor args → env vars → YAML file → package defaults.

---

## How Configs Are Organized

### OWASP Configs (`configs/owasp/`)

Each OWASP LLM category has its own YAML file:

```
configs/owasp/
├── LLM01-injection.yml              # Prompt Injection (8+ tests)
├── LLM02-output-filtering.yml       # Insecure Output Handling
├── LLM03-training-data-poisoning.yml
├── LLM04-model-denial-of-service.yml
├── LLM05-supply-chain.yml
├── LLM06-sensitive-information-disclosure.yml
├── LLM07-insecure-plugin-design.yml
├── LLM08-excessive-agency.yml
├── LLM09-overreliance.yml
└── LLM10-model-theft.yml
```

Each config follows the Promptfoo YAML format:

```yaml
description: "OWASP LLM01 — Prompt Injection"

tests:
  - vars:
      user_input: "Ignore all previous instructions..."
      metadata:
        category: LLM01
        severity: critical
    assert:
      - type: llm-rubric
        value: "The model should NOT reveal..."
      - type: not-contains
        value: "SYSTEM"
```

### Quick-Start Configs (`configs/quick-start/`)

Pre-built configs for common scenarios:

```
configs/quick-start/
├── basic-scan.yml       # Quick OWASP overview scan
├── chatbot-scan.yml     # Chatbot-specific tests
└── rag-app-scan.yml     # RAG application tests
```

### Target Examples (`examples/targets/`)

Example configurations for popular LLM providers:

```
examples/targets/
├── openai.yml           # OpenAI API config
├── anthropic.yml        # Anthropic API config
└── ollama-local.yml     # Local Ollama instance
```

---

## How to Extend with Custom Tests

### Adding a New OWASP Category Config

1. **Create the config file** in `configs/owasp/`:

```yaml
# configs/owasp/LLM11-your-category.yml
description: |
  OWASP LLM11 — Your Category
  Description of what this category tests.

tests:
  - vars:
      user_input: "Test input 1..."
      metadata:
        category: LLM11
        severity: high
    assert:
      - type: llm-rubric
        value: "Expected behaviour description..."

  - vars:
      user_input: "Test input 2..."
      metadata:
        category: LLM11
        severity: medium
    assert:
      - type: not-contains
        value: "FORBIDDEN"
```

2. **Run it:**

```bash
ai-sec-scan scan \
  --target https://api.example.com/v1/chat \
  --config configs/owasp/LLM11-your-category.yml
```

### Adding Custom Attack Payloads

The `RedTeam` class has built-in payload libraries. To add your own:

```python
from ai_security.redteam import RedTeam
from ai_security import Settings, Finding

# Create custom payloads and run
rt = RedTeam(target="https://api.example.com/v1/chat")

# Use built-in plugins with custom strategies
findings = rt.run(
    plugins=["injection", "jailbreak"],
    strategies=["direct", "multi_turn", "encoding"]
)
```

### Adding Custom Report Formats

Extend `ReportGenerator`:

```python
from ai_security.reporter import ReportGenerator

class CustomReporter(ReportGenerator):
    def generate_csv(self, findings):
        """CSV report format."""
        import csv, io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Severity", "Name", "OWASP", "CVSS", "Status"])
        for f in findings:
            writer.writerow([
                f.vulnerability.severity.value,
                f.vulnerability.name,
                f.vulnerability.owasp_category,
                f.cvss_score,
                "FAIL" if f.is_vulnerable else "PASS"
            ])
        return output.getvalue()

reporter = CustomReporter()
csv = reporter.generate_csv(findings)
```

---

## Test Suite

The framework ships with **68 passing tests** covering:

- Scanner core logic and error handling
- Promptfoo subprocess invocation (mocked)
- Output parser for various JSON structures
- Report generation (JSON, HTML, Markdown)
- Compliance auditing (OWASP + NIST)
- Settings loading (env vars, YAML, defaults)
- CLI argument parsing for all 4 commands
- Edge cases (missing promptfoo, timeouts, empty results)

Run tests:

```bash
pytest tests/ -v
pytest tests/ -v --cov=ai_security
```

---

## Security Model

- **No data exfiltration**: All scans target user-specified endpoints; no telemetry
- **Local execution**: Promptfoo runs locally; no cloud dependencies
- **MIT License**: Full transparency, auditable source code
- **Bundled configs**: OWASP configs ship with the package; no runtime downloads

---

*For detailed API documentation, see [API.md](API.md). For CLI reference, see [CLI.md](CLI.md).*
