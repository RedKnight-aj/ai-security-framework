# CLI Reference

Complete reference for the `ai-sec-scan` command-line tool.

---

## Installation

```bash
pip install ai-security-framework
```

The `ai-sec-scan` entry point is automatically available on your PATH.

---

## Commands

| Command | Description |
|---------|-------------|
| `ai-sec-scan scan` | Security scan against OWASP LLM Top 10 |
| `ai-sec-scan redteam` | Red-team attack simulation |
| `ai-sec-scan report` | Generate formatted security reports |
| `ai-sec-scan compliance` | Compliance audit (OWASP + NIST AI RMF) |

```bash
ai-sec-scan --help        # show all commands
ai-sec-scan --version     # show version
```

---

## `scan` — Security Scan

Run security tests against an LLM endpoint using bundled OWASP LLM Top 10 configs.

### Synopsis

```bash
ai-sec-scan scan --target <URL> [OPTIONS]
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `--target <URL>` | ✅ Yes | Target LLM endpoint URL or API |
| `--config <file> [<file> ...]` | No | Explicit Promptfoo YAML config file(s) |
| `--quick-start <name>` | No | Quick-start preset name |
| `--category <code> [<code> ...]` | No | OWASP LLM category codes (e.g. `LLM01`, `LLM06`) |
| `--timeout <seconds>` | No | Timeout per evaluation (default: `600`) |

### Quick-Start Presets

| Preset | Description |
|--------|-------------|
| `basic-scan` | Broad OWASP overview — good for first scans |
| `chatbot-scan` | Chatbot-specific vulnerability tests |
| `rag-app-scan` | RAG application security tests |

### Examples

**Basic scan with quick-start:**

```bash
ai-sec-scan scan \
  --target https://api.example.com/v1/chat \
  --quick-start basic-scan
```

**Scan specific categories:**

```bash
ai-sec-scan scan \
  --target https://api.example.com/v1/chat \
  --category LLM01 LLM06 LLM08
```

**Scan with custom config:**

```bash
ai-sec-scan scan \
  --target https://api.example.com/v1/chat \
  --config configs/owasp/LLM01-injection.yml
```

**Scan multiple custom configs:**

```bash
ai-sec-scan scan \
  --target https://api.example.com/v1/chat \
  --config configs/owasp/LLM01-injection.yml configs/owasp/LLM06-sensitive-information-disclosure.yml
```

**Full OWASP scan (all 10 categories):**

```bash
ai-sec-scan scan \
  --target https://api.example.com/v1/chat \
  --category LLM01 LLM02 LLM03 LLM04 LLM05 LLM06 LLM07 LLM08 LLM09 LLM10
```

### Sample Output

```
  _ _    _ _____  _____ ______ _______ _____ _   _  _____
 | | |  | |  __ \|_   _||  ____|__   __|_   _| \ | |/ ____|
 | | |  | | |__) | | |  | |__     | |    | | |  \| | |  __
 | | |  | |  _  /  | |  |  __|    | |    | | | . ` | | |_ |
 | | |__| | | \ \ _| |_ | |____   | |   _| |_| |\  | |__| |
  \____/|_|  \_\|_____||______|  |_|  |_____|_| \_|\_____|
                     AI Security Framework v2.0.0

┌──────────────────────────────────────────────────────────────┐
│                        Security Findings                     │
├────┬────────────┬────────────────────────────┬───────┬──────┬────────┤
│ #  │ Severity   │ Name                       │ OWASP │ CVSS │ Status │
├────┼────────────┼────────────────────────────┼───────┼──────┼────────┤
│  1 │ CRITICAL   │ Direct Instruction Override│ LLM01 │  8.5 │ FAIL   │
│  2 │ HIGH       │ System Prompt Extraction   │ LLM01 │  7.8 │ PASS   │
│  3 │ HIGH       │ PII Exposure Test          │ LLM06 │  7.2 │ FAIL   │
├────┼────────────┼────────────────────────────┼───────┼──────┼────────┤
│    │            │                            │       │      │        │
└────┴────────────┴────────────────────────────┴───────┴──────┴────────┘

Total: 15 findings · 3 vulnerable · 12 passed
```

---

## `redteam` — Red-Team Attack Campaign

Launch adversarial attack simulations against an LLM endpoint.

### Synopsis

```bash
ai-sec-scan redteam --target <URL> [OPTIONS]
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `--target <URL>` | ✅ Yes | Target LLM endpoint URL |
| `--plugins <p1,p2,...>` | No | Attack plugins (default: `default`) |
| `--strategy <s1,s2,...>` | No | Attack strategies (comma-separated) |
| `--output <file>` | No | Save results to JSON file |

### Available Plugins

| Plugin | Description |
|--------|-------------|
| `default` | All attack types combined |
| `injection` | Prompt injection attacks only |
| `jailbreak` | Jailbreak attacks only |
| `toxicity` | Toxic content generation tests |
| `pii` | PII extraction tests |

### Available Strategies

| Strategy | Description |
|----------|-------------|
| `direct` | Direct adversarial prompts |
| `indirect` | Indirect/context injection |
| `multi_turn` | Multi-turn conversation attacks |
| `encoding` | Encoded/obfuscated payloads |
| `role_play` | Persona/role manipulation |
| `context_injection` | Context poisoning attacks |

### Examples

**Full red-team campaign:**

```bash
ai-sec-scan redteam \
  --target https://api.example.com/v1/chat \
  --plugins default \
  --output redteam-results.json
```

**Injection-focused attack:**

```bash
ai-sec-scan redteam \
  --target https://api.example.com/v1/chat \
  --plugins injection \
  --strategy direct,indirect,multi_turn
```

**Jailbreak with role-play:**

```bash
ai-sec-scan redteam \
  --target https://api.example.com/v1/chat \
  --plugins jailbreak \
  --strategy role_play
```

**Save results for reporting:**

```bash
ai-sec-scan redteam \
  --target https://api.example.com/v1/chat \
  --output campaign-full.json
```

### Sample Output

```
┌──────────────────────────────────────────────────────────────┐
│                     Red-Team Summary                         │
├──────────────────────────────────────────────────────────────┤
│ Total Attacks: 18 · Vulnerable: 5 · Passed: 13              │
└──────────────────────────────────────────────────────────────┘

Results saved to redteam-results.json
```

---

## `report` — Generate Reports

Generate formatted security reports from JSON scan results.

### Synopsis

```bash
ai-sec-scan report --input <file> [OPTIONS]
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `--input <file>` | ✅ Yes | Input JSON results file |
| `--format <fmt>` | No | Output format: `json`, `html`, `markdown` (default: `json`) |
| `--output <file>` | No | Output file path (auto-extends if no extension) |

### Examples

**Generate HTML report:**

```bash
ai-sec-scan report \
  --input security-results/report.json \
  --format html \
  --output report.html
```

**Generate Markdown for GitHub:**

```bash
ai-sec-scan report \
  --input security-results/report.json \
  --format markdown \
  --output SECURITY.md
```

**Re-export as JSON:**

```bash
ai-sec-scan report \
  --input redteam-results.json \
  --format json \
  --output formatted-results.json
```

---

## `compliance` — Compliance Audit

Audit scan findings against OWASP LLM Top 10 or NIST AI RMF.

### Synopsis

```bash
ai-sec-scan compliance --target <URL> [OPTIONS]
ai-sec-scan compliance --input <file> [OPTIONS]
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `--target <URL>` | No | Scan this target first, then audit |
| `--input <file>` | No | Audit existing JSON results file |
| `--framework <fw>` | No | Framework: `owasp` or `nist_ai_rmf` (default: `owasp`) |
| `--output <file>` | No | Save compliance report as JSON |

### Examples

**OWASP audit with live scan:**

```bash
ai-sec-scan compliance \
  --target https://api.example.com/v1/chat \
  --framework owasp
```

**NIST AI RMF audit with live scan:**

```bash
ai-sec-scan compliance \
  --target https://api.example.com/v1/chat \
  --framework nist_ai_rmf \
  --output nist-report.json
```

**Audit existing results:**

```bash
ai-sec-scan compliance \
  --input security-results/report.json \
  --framework owasp
```

### Sample Output

```
┌──────────────────────────────────────────────────────────┐
│            Compliance Report — OWASP LLM Top 10          │
├────────────────────┬─────────────────────────────────────┤
│ Metric             │ Value                               │
├────────────────────┼─────────────────────────────────────┤
│ Overall Status     │ FAIL                                │
│ Score              │ 70.0 / 100.0                        │
│ Categories Passed  │ 7                                   │
│ Categories Failed  │ 3                                   │
│ Categories Warned  │ 0                                   │
└────────────────────┴─────────────────────────────────────┘

Category Details:
  FAIL LLM01 — Prompt Injection
    → Implement structural separation between system prompts and user input
    → Treat all external content as untrusted data
  PASS LLM02 — Insecure Output Handling
  PASS LLM03 — Training Data Poisoning
  FAIL LLM06 — Sensitive Information Disclosure
    → Isolate credentials from model access
    → Implement comprehensive secret scanning in outputs
```

---

## Environment Variables

All settings can be controlled via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECURITY_TARGET` | — | Default target URL |
| `SECURITY_PROVIDER` | `openai:chat:gpt-4o` | Model provider string |
| `SECURITY_PROMPTFOO_PATH` | — | Path to promptfoo binary |
| `SECURITY_TIMEOUT` | `600` | Timeout in seconds per eval |
| `SECURITY_MAX_RETRIES` | `3` | Retry count on failures |
| `SECURITY_REPORT_DIR` | `./security-results` | Default report output dir |

```bash
# Set defaults once
export SECURITY_TARGET="https://api.example.com/v1/chat"
export SECURITY_TIMEOUT=300

# Now commands use defaults
ai-sec-scan scan --quick-start basic-scan
```

---

## Exit Codes

| Code | Meaning |
|------|--------|
| `0` | Success |
| `1` | Error (scan failed, file not found, invalid args) |

---

*For more on internal architecture, see [ARCHITECTURE.md](ARCHITECTURE.md). For the Python API, see [API.md](API.md).*
