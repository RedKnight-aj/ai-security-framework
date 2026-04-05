# CONTRIBUTING.md — How to Contribute

## Getting Started

```bash
git clone https://github.com/RedKnight-aj/ai-security-framework.git
cd ai-security-framework
pip install -e ".[dev]"
```

## Development Workflow

1. **Fork** the repository
2. **Create a branch** for your feature/fix:
   ```bash
   git checkout -b feature/my-improvement
   ```
3. **Write tests** — all new code must have corresponding tests
4. **Run the test suite**:
   ```bash
   pytest tests/
   ```
5. **Lint and format**:
   ```bash
   black src/ tests/
   mypy src/
   ruff check src/ tests/
   ```
6. **Commit and push**:
   ```bash
   git add -A
   git commit -m "feat: add new vulnerability detection pattern"
   git push origin feature/my-improvement
   ```
7. **Open a Pull Request**

## Code Standards

### Type Hints
All functions must have complete type hints:
```python
from __future__ import annotations
from typing import List, Optional

def process_findings(
    findings: List[Finding],
    limit: Optional[int] = None,
) -> List[Finding]:
    ...
```

### Docstrings
All public classes and functions must have docstrings:
```python
class SecurityScanner:
    """Main entry-point for AI security scanning.

    Args:
        target: URL or API endpoint to scan.
        settings: Optional Settings override.
    """
```

### No `eval()` or `exec()`
The codebase must never contain `eval()` or `exec()`.

### Error Handling
- Use specific exceptions (not bare `except:`)
- Provide meaningful error messages
- Use retries for transient failures

### Testing
- **Happy path**, **edge cases**, and **errors** for every class
- Use `pytest.fixtures` for shared test data
- Mock external calls (Promptfoo subprocess, network requests)

## Adding New OWASP Categories

1. Create config in `configs/owasp/LLMXX-category-name.yml`
2. Add category metadata to `compliance.py` → `_OWASP_CATEGORIES`
3. Add remediation to `compliance.py` → `_OWASP_RECOMMENDATIONS`
4. Add vulnerability type enum entry in `scanner.py` → `VulnerabilityType`
5. Write tests for the new category

## Adding New Report Formats

1. Add format to `ReportFormat` enum in `reporter.py`
2. Add `generate_<format>()` method to `ReportGenerator`
3. Update `_build_html()`, `_build_markdown()`, etc. as needed
4. Write tests for HTML sanitization and format correctness

## Release Process

1. Update version in `pyproject.toml`
2. Update `__version__` in `__init__.py`
3. Update CHANGELOG.md
4. `git tag v2.0.0`
5. `git push origin --tags`

## Questions?

Open an issue with the `question` label or reach out on Discord.
