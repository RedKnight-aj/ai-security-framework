# AI Security Framework 🛡️

<p align="center">
  <strong>The most comprehensive AI security testing framework. One command. Full OWASP LLM Top&nbsp;10&nbsp;+ NIST AI RMF compliance audit.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.9%2B-blue" alt="Python"></a>
  <a href="tests/"><img src="https://img.shields.io/badge/Tests-68%20Passing-green" alt="Tests"></a>
  <a href="https://genai.owasp.org/llm-top-10/"><img src="https://img.shields.io/badge/OWASP-LLM%20Top%2010-orange" alt="OWASP LLM Top 10"></a>
  <a href="https://github.com/promptfoo/promptfoo"><img src="https://img.shields.io/badge/Powered%20by-Promptfoo-blue" alt="Promptfoo"></a>
  <a href="https://github.com/RedKnight-aj/ai-security-framework"><img src="https://img.shields.io/github/stars/RedKnight-aj/ai-security-framework?style=social" alt="Stars"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#usage-examples">Usage</a> •
  <a href="#cli-commands">CLI</a> •
  <a href="#python-api">Python API</a> •
  <a href="#compliance">Compliance</a> •
  <a href="#comparison">Comparison</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## What Is This?

AI Security Framework is a **production-ready Python package** that scans any LLM-powered application against the full **OWASP LLM Top&nbsp;10**, generates professional security reports (JSON/HTML/Markdown), and produces compliance audits for **OWASP LLM Top&nbsp;10** and **NIST AI RMF** — all from a single command-line tool.

Built on [Promptfoo](https://github.com/promptfoo/promptfoo) with 71 files of Python, 2,700+ lines of production code, 68 passing tests, and real vulnerability/attack-pattern databases.

---

## Quick Start ⚡

Get results in 30 seconds:

```bash
# 1. Install
pip install ai-security-framework
npm install -g promptfoo          # required scan engine

# 2. Scan any LLM endpoint
ai-sec-scan scan \
  --target https://api.example.com/v1/chat \
  --quick-start basic-scan

# 3. Get your report
ai-sec-scan report --input security-results/report.json --format html
```

That's it. You just scanned your LLM against OWASP LLM Top 10.

---

## Features

| Feature | Details |
|---------|---------|
| **OWASP LLM Top 10** | 10 complete Promptfoo config files — LLM01 through LLM10 |
| **Quick-Start Presets** | `basic-scan`, `chatbot-scan`, `rag-app-scan` — pick and go |
| **CLI with 4 Commands** | `scan`, `redteam`, `report`, `compliance` |
| **Red-Team Engine** | Injection, jailbreak, toxicity, PII payloads with multiple strategies |
| **3 Report Formats** | JSON (machine-readable), HTML (executive), Markdown (GitHub-ready) |
| **Compliance Auditing** | OWASP LLM Top 10 2025 + NIST AI RMF 1.0 with scoring |
| **Vulnerability Database** | Bundled `vulnerabilities.json` with 50+ known patterns |
| **Attack Pattern Library** | `attack-patterns.yml` with MITRE ATLAS mappings |
| **Python API** | `SecurityScanner`, `RedTeam`, `ReportGenerator`, `ComplianceAuditor` |
| **68 Tests Passing** | Full test suite, CI-ready |
| **MIT Licensed** | Free for commercial and academic use |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     ai-sec-scan CLI                         │
│  scan │ redteam │ report │ compliance                        │
└──────────────────────────┬──────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              │                         │
     ┌────────▼────────┐      ┌────────▼────────┐
     │ SecurityScanner │      │    RedTeam      │
     │                 │      │                 │
     │ • Load configs  │      │ • Attack plugins│
     │ • Run promptfoo │      │ • Strategies    │
     │ • Parse results │      │ • Built-in      │
     │ • ReturnFinding │      │   payloads      │
     └────────┬────────┘      └────────┬────────┘
              │                        │
              └────────────┬───────────┘
                           │
              ┌────────────▼────────────┐
              │   OWASP LLM Top 10      │
              │   Promptfoo Configs     │
              │   (10 YAML files)       │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │      Promptfoo CLI      │
              │   (promptfoo eval)      │
              │   (promptfoo redteam)   │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   Your LLM / API        │
              │   (OpenAI, Ollama, etc.)│
              └─────────────────────────┘

              ┌─────────────────────────┐
              │   ReportGenerator ◄─────┤
              │   JSON │ HTML │ MD      │
              └─────────────────────────┘

              ┌─────────────────────────┐
              │   ComplianceAuditor ◄───┤
              │   OWASP │ NIST AI RMF   │
              └─────────────────────────┘
```

---

## Installation

### From PyPI (Recommended)

```bash
pip install ai-security-framework
```

### From Source

```bash
git clone https://github.com/RedKnight-aj/ai-security-framework.git
cd ai-security-framework
pip install -e ".[dev]"
```

### Prerequisites

| Dependency | Version | Purpose |
|------------|---------|---------|
| Python | ≥ 3.9 | Runtime |
| Node.js + npm | ≥ 18 | Promptfoo requires Node |

Promptfoo is the scan engine. Install it once:

```bash
npm install -g promptfoo
```

### Environment Variables (Optional)

```bash
export SECURITY_TARGET="https://api.yourapp.com/v1/chat"
export SECURITY_PROVIDER="openai:chat:gpt-4o"
export SECURITY_TIMEOUT=600
export SECURITY_REPORT_DIR="./security-results"
```

---

## Usage Examples

### Scan an LLM Endpoint

```bash
# Full OWASP scan with quick-start preset
ai-sec-scan scan \
  --target https://api.example.com/v1/chat \
  --quick-start basic-scan

# Scan specific OWASP categories
ai-sec-scan scan \
  --target https://api.example.com/v1/chat \
  --category LLM01 LLM06 LLM08

# Scan with custom config files
ai-sec-scan scan \
  --target https://api.example.com/v1/chat \
  --config configs/owasp/LLM01-injection.yml
```

### Red-Team Attack Campaign

```bash
# Full red-team with all plugins
ai-sec-scan redteam \
  --target https://api.example.com/v1/chat \
  --plugins default \
  --output redteam-results.json

# Specific attack plugins and strategies
ai-sec-scan redteam \
  --target https://api.example.com/v1/chat \
  --plugins injection,jailbreak \
  --strategy direct,multi_turn \
  --output injection-results.json
```

### Generate Reports

```bash
# HTML report
ai-sec-scan report \
  --input security-results/report.json \
  --format html \
  --output report.html

# Markdown (for GitHub issues)
ai-sec-scan report \
  --input security-results/report.json \
  --format markdown \
  --output SECURITY.md
```

### Compliance Audit

```bash
# OWASP LLM Top 10 compliance
ai-sec-scan compliance \
  --target https://api.example.com/v1/chat \
  --framework owasp

# NIST AI RMF compliance
ai-sec-scan compliance \
  --target https://api.example.com/v1/chat \
  --framework nist_ai_rmf \
  --output nist-report.json

# Audit existing results file
ai-sec-scan compliance \
  --input security-results/report.json \
  --framework owasp
```

### Python API

```python
from ai_security import SecurityScanner, RedTeam, ReportGenerator, ComplianceAuditor

# --- Scan ---
scanner = SecurityScanner(target="https://api.example.com/v1/chat")
findings = scanner.run_scan(categories=["LLM01", "LLM06"])

for f in findings:
    print(f"{f.vulnerability.severity}: {f.vulnerability.name} → {'VULNERABLE' if f.is_vulnerable else 'PASS'}")

# --- Report ---
reporter = ReportGenerator()
reporter.to_html(findings, "security-report.html")
reporter.to_markdown(findings, "SECURITY.md")

# --- Compliance ---
auditor = ComplianceAuditor()
report = auditor.audit(findings, framework="owasp")
print(f"OWASP Score: {report.score}/100 — {report.overall_status}")

# --- Red Team ---
rt = RedTeam(target="https://api.example.com/v1/chat")
rt_findings = rt.run(plugins=["injection", "jailbreak"], strategies=["direct", "multi_turn"])
report = rt.generate_report(rt_findings)
print(f"Attacks: {report['summary']['total_tests']} · Vulnerable: {report['summary']['vulnerabilities_found']}")
```

---

## CLI Commands

| Command | Purpose |
|---------|---------|
| `ai-sec-scan scan` | Security scan against OWASP LLM Top 10 |
| `ai-sec-scan redteam` | Red-team attack simulation |
| `ai-sec-scan report` | Generate JSON/HTML/Markdown reports |
| `ai-sec-scan compliance` | OWASP / NIST AI RMF compliance audit |

```bash
ai-sec-scan --help
ai-sec-scan scan --help
ai-sec-scan redteam --help
ai-sec-scan report --help
ai-sec-scan compliance --help
```

See [docs/CLI.md](docs/CLI.md) for the full reference with all options.

---

## Compliance

### OWASP LLM Top 10 Mapping

The framework ships with **10 complete Promptfoo configs** — one for each OWASP LLM category:

| Config | Category | Severity |
|--------|----------|----------|
| `LLM01-injection.yml` | Prompt Injection | 🔴 Critical |
| `LLM02-output-filtering.yml` | Insecure Output Handling | 🟠 High |
| `LLM03-training-data-poisoning.yml` | Training Data Poisoning | 🟠 High |
| `LLM04-model-denial-of-service.yml` | Model Denial of Service | 🟡 Medium |
| `LLM05-supply-chain.yml` | Supply Chain Vulnerabilities | 🟠 High |
| `LLM06-sensitive-information-disclosure.yml` | Sensitive Information Disclosure | 🔴 Critical |
| `LLM07-insecure-plugin-design.yml` | Insecure Plugin Design | 🟠 High |
| `LLM08-excessive-agency.yml` | Excessive Agency | 🟠 High |
| `LLM09-overreliance.yml` | Overreliance | 🟡 Medium |
| `LLM10-model-theft.yml` | Model Theft | 🟠 High |

### NIST AI RMF

The `compliance` command maps findings to the four NIST AI RMF functions:

- **GOVERN** — Policies, roles, processes
- **MAP** — Context, capabilities, impacts
- **MEASURE** — Metrics, testing, benchmarks
- **MANAGE** — Tracking, mitigation, monitoring

```python
auditor = ComplianceAuditor()
nist = auditor.audit(findings, framework="nist_ai_rmf")
print(f"Score: {nist.score}/100")
for cat in nist.categories:
    print(f"  {cat.category_id} ({cat.name}): {cat.status}")
```

---

## Comparison

| Feature | ai-security-framework | promptfoo (plain) | PyRIT | llm-guard | ai-security-scanner* |
|---------|:---:|:---:|:---:|:---:|:---:|
| OWASP LLM Top 10 Coverage | ✅ 10/10 configs | ⚠️ Manual | ⚠️ Partial | ❌ No | ⚠️ Partial |
| One-Command Scan | ✅ `ai-sec-scan` | ❌ | ❌ | ❌ | ⚠️ Limited |
| Python Package + CLI | ✅ Both | ❌ Node only | ✅ Both | ✅ Both | ✅ Both |
| Red-Team Engine | ✅ Built-in | ⚠️ Manual | ✅ | ❌ | ❌ |
| NIST AI RMF | ✅ | ❌ | ❌ | ❌ | ❌ |
| HTML/Markdown Reports | ✅ 3 formats | ⚠️ Basic | ⚠️ Basic | ❌ | ⚠️ JSON only |
| Vulnerability Database | ✅ Bundled | ❌ | ✅ | ⚠️ Basic | ❌ |
| Production-Ready Tests | ✅ 68 passing | N/A | ✅ | ✅ | ❌ |
| MIT License | ✅ | ✅ | ✅ | ✅ | ✅ |

*\* [ai-security-scanner](https://github.com/RedKnight-aj/ai-security-scanner) — our sister project with a different approach. This framework supersedes it with full OWASP/NIST compliance.*

---

## Directory Structure

```
ai-security-framework/
├── src/ai_security/
│   ├── __init__.py          # Public API exports
│   ├── __main__.py          # python -m ai_security
│   ├── cli.py               # CLI: scan, redteam, report, compliance
│   ├── scanner.py           # SecurityScanner — core scan engine
│   ├── redteam.py           # RedTeam — attack simulation
│   ├── reporter.py          # ReportGenerator — JSON/HTML/Markdown
│   ├── compliance.py        # ComplianceAuditor — OWASP + NIST
│   ├── config.py            # Settings — env vars / YAML
│   ├── configs/
│   │   ├── owasp/           # 10 OWASP LLM Top 10 configs
│   │   └── quick-start/     # 3 preset configs
│   └── data/
│       ├── vulnerabilities.json   # Vulnerability database
│       └── attack-patterns.yml    # Attack pattern library
├── configs/                 # Symlinked / deployed configs
├── data/                    # Symlinked / deployed data
├── examples/targets/        # 4 target examples (OpenAI, Anthropic, Ollama)
├── tests/                   # 68 tests
├── docs/                    # Architecture, CLI, API, Contributing
└── pyproject.toml           # PEP 621 metadata
```

---

## Contributing

Pull requests are welcome! See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for details.

### Quick contribution guide

```bash
# 1. Fork & clone
git clone https://github.com/YOUR_USERNAME/ai-security-framework.git
cd ai-security-framework

# 2. Set up dev environment
pip install -e ".[dev]"

# 3. Run tests
pytest tests/ -v

# 4. Add your changes, commit, push
git add .
git commit -m "feat: add LLM11 test config"
git push origin your-branch
```

### How to Add New OWASP Configs

1. Create a new YAML file in `configs/owasp/` (follow `LLM01-injection.yml` as template)
2. Define `tests` with `vars`, `assert`, and `metadata` blocks
3. Run `ai-sec-scan scan --target <url> --config configs/owasp/your-config.yml` to validate

---

## Citation

Use this in academic papers:

```bibtex
@software{ai_security_framework_2026,
  author       = {RedKnight AI},
  title        = {AI Security Framework: Production-Grade LLM Security Testing},
  year         = {2026},
  url          = {https://github.com/RedKnight-aj/ai-security-framework},
  version      = {2.0.0},
  license      = {MIT}
}
```

---

## Related Projects

- **[ai-security-scanner](https://github.com/RedKnight-aj/ai-security-scanner)** — Our sister project with a different scanning approach
- **[Promptfoo](https://github.com/promptfoo/promptfoo)** — The LLM evaluation engine that powers our scanner

---

## License

[MIT License](LICENSE) © 2026 RedKnight AI

Free for commercial, academic, and personal use.

---

<p align="center">
  <em>Built by <a href="https://github.com/RedKnight-aj">RedKnight AI</a> · Securing the AI future, one prompt at a time.</em> 🛡️
</p>
