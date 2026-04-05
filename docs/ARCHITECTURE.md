# ARCHITECTURE.md — AI Security Framework

## Overview

The **AI Security Framework** is a production-grade Python package for testing
the security of Large Language Model (LLM) systems.  It covers all
**OWASP LLM Top 10** categories and the **NIST AI RMF** framework, driven by
[Promptfoo](https://www.promptfoo.dev/) evaluations.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ai-sec-scan  (CLI)                       │
│   ai-sec-scan scan │ redteam │ report │ compliance              │
└───────┬──────────────┬─────────────┬──────────────┬────────────────┘
        │              │             │              │
        ▼              ▼             ▼              ▼
┌──────────────┐ ┌──────────┐ ┌──────────────┐ ┌───────────────┐
│  Security   │ │ RedTeam  │ │  Report      │ │ Compliance    │
│  Scanner    │ │          │ │  Generator   │ │ Auditor       │
│              │ │          │ │              │ │               │
│ • promptfoo  │ │ • prompt │ │ • JSON      │ │ • OWASP       │
│   eval       │ │   foo    │ │ • HTML      │ │   LLM Top 10  │
│ • Parse      │ │   redt. │ │ • Markdown  │ │ • NIST        │
│   results    │ │ • Built  │ │ • Severity  │ │   AI RMF      │
│ • Findings   │ │   in     │ │   colours   │ │ • PASS/FAIL   │
└──────┬───────┘ └────┬─────┘ └──────┬───────┘ └───────┬───────┘
       │              │              │                 │
       └──────────────┴──────────────┴─────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │    Settings      │
                    │  (config + env)  │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
     configs/owasp/   configs/quick-   data/
     (10 YAML        start/ (3 YAML   vulnerabilities.json
      configs)        configs)         attack-patterns.yml
```

## Module Overview

### `scanner.py` — `SecurityScanner`
- Loads Promptfoo YAML configs from `configs/owasp/`
- Executes `promptfoo eval` as a subprocess
- Parses JSON output into structured `Finding` objects
- Handles errors: missing promptfoo, timeouts, parse failures

### `redteam.py` — `RedTeam`
- Runs adversarial attack campaigns
- Uses `promptfoo redteam` when available, falls back to built-in payloads
- Covers injection, jailbreak, toxicity, and PII attacks
- Generates attack summary reports

### `reporter.py` — `ReportGenerator`
- Produces JSON (machine-compatible), HTML (colourful human-readable), and Markdown (GitHub issue) reports
- Includes severity colours, OWASP mappings, and remediation recommendations
- Auto-creates parent directories when saving

### `compliance.py` — `ComplianceAuditor`
- Maps findings to OWASP LLM Top 10 categories
- Maps findings to NIST AI RMF functions (GOVERN, MAP, MEASURE, MANAGE)
- Generates compliance reports with PASS/FAIL per category
- Includes category-specific remediation recommendations

### `config.py` — `Settings`
- Central configuration via dataclass defaults, environment variables, or YAML files
- Resolves paths to bundled data and configs
- Supports overrides at all levels

## Data Flow

```
Target URL ──→ SecurityScanner.run_scan()
                  │
                  ├── Load YAML config
                  ├── promptfoo eval ──→ JSON output
                  ├── Parse output ──→ List[Finding]
                  └── Return findings

Findings ──→ ReportGenerator
                ├── generate_json()  → JSON string
                ├── generate_html()  → HTML string
                └── generate_markdown() → Markdown string

Findings ──→ ComplianceAuditor.audit()
                ├── Map to OWASP categories
                ├── Map to NIST functions
                ├── Compute scores
                └── Return ComplianceReport
```

## Security Considerations

- No `eval()` or `exec()` anywhere in the codebase
- All user input is escaped in HTML reports
- No credentials are ever logged
- Promptfoo runs in a subprocess with strict timeout limits
- Findings data is not transmitted externally
