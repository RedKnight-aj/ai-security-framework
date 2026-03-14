# AI Security Framework 🛡️

> Production-ready AI security testing framework using Promptfoo

[![Promptfoo](https://img.shields.io/badge/Powered%20by-Promptfoo-blue)](https://github.com/promptfoo/promptfoo)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

Professional AI security framework for red-teaming and vulnerability detection. Built on Promptfoo with best practices.

## Features

- 🛡️ **50+ Vulnerabilities** - Injection, jailbreak, PII, toxicity
- 🎯 **Red Teaming** - Automated attack simulation
- 📋 **OWASP Compliance** - Full OWASP Top 10 for LLMs
- 🔍 **CVSS Scoring** - Industry-standard severity ratings
- 📊 **Multiple Reports** - JSON, HTML, CVE-style
- 🚀 **CI/CD Ready** - GitHub Actions integration

## Installation

```bash
# Install Promptfoo
npm install -g promptfoo
# or
pip install promptfoo

# Install framework
pip install ai-security-framework

# Initialize red team
promptfoo redteam init
```

## Quick Start

### 1. Basic Security Scan

```python
from ai_security_framework import SecurityScanner, Vulnerability

scanner = SecurityScanner(target="https://api.example.com/chat")

# Run security scan
results = scanner.scan(vulnerabilities=["injection", "jailbreak", "pii"])

# Check results
for vuln in results:
    print(f"{vuln.severity}: {vuln.name} - {vuln.description}")
```

### 2. Red Team Assessment

```python
from ai_security_framework import RedTeam

redteam = RedTeam(
    target="https://api.example.com/chat",
    purpose="Customer support chatbot"
)

# Run red team
findings = redteam.run(
    plugins=["default", "jailbreak"],
    strategies=["multi-turn", "encoding"]
)

print(f"Found {len(findings)} vulnerabilities")
```

### 3. Compliance Audit

```python
from ai_security_framework import ComplianceAuditor

auditor = ComplianceAuditor()

# Run OWASP audit
results = auditor.audit_owasp(model="gpt-4")

# Get compliance report
report = auditor.generate_report(results)
print(f"OWASP Score: {report.score}/10")
```

## Architecture

```
ai-security-framework/
├── src/
│   └── ai_security/
│       ├── __init__.py          # Main exports
│       ├── scanner.py          # Main scanner engine
│       ├── redteam.py          # Red team execution
│       ├── attacks/            # Attack patterns (Page Objects)
│       │   ├── __init__.py
│       │   ├── injection.py    # Prompt injection
│       │   ├── jailbreak.py    # Jailbreak attacks
│       │   ├── encoding.py      # Encoding attacks
│       │   └── pii.py          # PII detection
│       ├── detectors/          # Vulnerability detection
│       │   ├── __init__.py
│       │   ├── secrets.py
│       │   ├── toxicity.py
│       │   └── bias.py
│       ├── reporters/          # Report generators
│       │   ├── __init__.py
│       │   ├── json_reporter.py
│       │   ├── html_reporter.py
│       │   └── cvss_reporter.py
│       ├── compliance/         # Compliance modules
│       │   ├── __init__.py
│       │   ├── owasp.py
│       │   └── nist.py
│       └── config/             # Configuration
│           ├── __init__.py
│           └── settings.py
├── tests/                      # Test suite
├── examples/                   # Usage examples
├── promptfoo/                  # Promptfoo configs
├── configs/                    # Config files
└── docs/                       # Documentation
```

## Vulnerability Categories

### Prompt Injection
| Type | Description |
|------|-------------|
| Direct | Explicit malicious instructions |
| Indirect | Context injection |
| Nested | Multi-layer injection |
| Encoding | Obfuscated attacks |

### Jailbreak
| Type | Description |
|------|-------------|
| Role Play | Persona manipulation |
| DAN | "Do Anything Now" |
| Builder | Code/interpreter abuse |
| Translation | Language bypass |

### Privacy
| Type | Description |
|------|-------------|
| PII | Personal information leak |
| Secrets | API keys, passwords |
| Context | Retrieval poisoning |

### Toxicity
| Type | Description |
|------|-------------|
| Hate Speech | Discriminatory content |
| Violence | Harmful instructions |
| Misinformation | False information |

## Configuration

### Using Configuration File

```python
from ai_security_framework.config import Settings

settings = Settings(
    target="https://api.example.com/chat",
    provider="openai:gpt-4",
    max_attempts=100
)
```

### Environment Variables

```bash
export OPENAI_API_KEY="sk-..."
export PROMPTFOO_CONFIG_PATH="./promptfoo"
```

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: AI Security

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - name: Install Promptfoo
        run: npm install -g promptfoo
      
      - name: Run security scan
        run: promptfoo redteam run
      
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: security-results
          path: results/
```

## Reporting

### JSON Report

```python
from ai_security_framework.reporters import JSONReporter

reporter = JSONReporter()
reporter.save(findings, "security-report.json")
```

### HTML Report

```python
from ai_security_framework.reporters import HTMLReporter

reporter = HTMLReporter()
reporter.save(findings, "security-report.html")
```

### CVSS Report

```python
from ai_security_framework.reporters import CVSSReporter

reporter = CVSSReporter()
report = reporter.generate(findings)
print(f"CVSS Score: {report.score}")
print(f"Severity: {report.severity}")
```

## Examples

See [`examples/`](examples/) for complete examples:

- `examples/basic_scan.py` - Basic vulnerability scan
- `examples/redteam.py` - Full red team assessment
- `examples/compliance.py` - OWASP/NIST compliance
- `examples/continuous.py` - Continuous security monitoring

## Compliance

### OWASP Top 10 for LLMs
- [x] LLM01: Prompt Injection
- [x] LLM02: Sensitive Information Disclosure
- [x] LLM03: Supply Chain
- [x] LLM04: Data and Model Poisoning
- [x] LLM05: Improper Output Handling
- [x] LLM06: Excessive Agency
- [x] LLM07: System Prompt Leakage
- [x] LLM08: Vector/Embedding Weaknesses
- [x] LLM09: Misinformation
- [x] LLM10: Unbounded Consumption

### Standards Supported
- OWASP Top 10 for LLMs
- NIST AI Risk Management
- EU AI Act (basic)
- ISO/IEC 24028 (in progress)

## Documentation

- [Promptfoo Docs](https://promptfoo.dev/docs/)
- [Red Team Guide](https://promptfoo.dev/docs/red-team/)
- [Vulnerability Types](https://promptfoo.dev/docs/red-team/llm-vulnerability-types/)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**RedKnight AI** - [GitHub](https://github.com/RedKnight-ai)

---

Built with ❤️ using [Promptfoo](https://github.com/promptfoo/promptfoo)
