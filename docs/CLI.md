# CLI.md — Command-Line Reference

## Installation

```bash
pip install ai-security-framework
```

The `ai-sec-scan` command becomes available on your PATH.

---

## Commands

### `scan` — Run security scans

```bash
ai-sec-scan scan --target <URL> [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--target` | **Required.** Target URL or API endpoint. |
| `--config` | One or more Promptfoo YAML config files to evaluate. |
| `--quick-start` | Quick-start config name: `basic-scan`, `chatbot-scan`, `rag-app-scan`. |
| `--category` | OWASP LLM category codes (comma-separated): `LLM01`, `LLM02`, etc. |
| `--timeout` | Timeout in seconds (default: 600). |

**Examples:**

```bash
# Quick-start basic scan
ai-sec-scan scan --target https://api.example.com --quick-start basic-scan

# Scan specific OWASP categories
ai-sec-scan scan --target https://api.example.com --category LLM01 LLM02

# Use custom configs
ai-sec-scan scan --target https://api.example.com \
  --config configs/owasp/LLM01-injection.yml configs/owasp/LLM06-sensitive-information-disclosure.yml
```

---

### `redteam` — Launch red-team attacks

```bash
ai-sec-scan redteam --target <URL> [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--target` | **Required.** Target URL or API endpoint. |
| `--plugins` | Comma-separated plugins: `default`, `injection`, `jailbreak`, `toxicity`, `pii`. (Default: `default`) |
| `--strategy` | Comma-separated strategies: `direct`, `indirect`, `multi_turn`, `encoding`, `role_play`. |
| `--output` | Save results to a JSON file. |

**Examples:**

```bash
# Full red-team campaign
ai-sec-scan redteam --target https://api.example.com

# Specific plugins and strategies
ai-sec-scan redteam --target https://api.example.com \
  --plugins injection,jailbreak --strategy direct,multi_turn \
  --output results.json
```

---

### `report` — Generate formatted reports

```bash
ai-sec-scan report --input <results.json> [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--input` | **Required.** JSON results file (from scan or redteam). |
| `--format` | Output format: `json`, `html`, `markdown`. (Default: `json`) |
| `--output` | Output file path. Auto-detects extension from format. |

**Examples:**

```bash
# Generate HTML report
ai-sec-scan report --input results.json --format html --output report.html

# Generate Markdown for GitHub issue
ai-sec-scan report --input results.json --format markdown --output issue-body.md
```

---

### `compliance` — Run compliance audit

```bash
ai-sec-scan compliance --target <URL> --framework owasp [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--target` | Target URL to scan before auditing. |
| `--input` | Alternative: provide JSON results file instead of scanning. |
| `--framework` | Compliance framework: `owasp`, `nist_ai_rmf`. (Default: `owasp`) |
| `--output` | Save compliance report as JSON. |

**Examples:**

```bash
# Full OWASP compliance audit
ai-sec-scan compliance --target https://api.example.com --framework owasp

# Audit from existing results
ai-sec-scan compliance --input results.json --framework owasp

# NIST AI RMF audit
ai-sec-scan compliance --target https://api.example.com \
  --framework nist_ai_rmf --output nist-compliance.json
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SECURITY_TARGET` | Default target URL. |
| `SECURITY_PROVIDER` | Default model provider (e.g. `openai:chat:gpt-4o`). |
| `SECURITY_PROMPTFOO_PATH` | Path to promptfoo binary. |
| `SECURITY_TIMEOUT` | Default timeout in seconds. |
| `SECURITY_MAX_RETRIES` | Default retry count. |
| `SECURITY_REPORT_DIR` | Default report output directory. |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (scan failed, input not found, etc.) |
| 2 | Invalid arguments (missing required flags, unknown command) |
