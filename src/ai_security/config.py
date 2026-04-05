"""
Configuration management for the AI Security Framework.

Provides a :class:`Settings` dataclass with sensible defaults, environment-
variable overrides, and YAML-file loading.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


@dataclass
class Settings:
    """Central configuration container for the AI Security Framework.

    All attributes have sensible defaults and can be overridden via
    environment variables or a YAML configuration file.

    Attributes:
        target: Target URL or API endpoint to scan.
        provider: Model provider string (e.g. ``openai:chat:gpt-4o``).
        promptfoo_path: Path to the Promptfoo binary (``None`` for PATH lookup).
        timeout_sec: Maximum seconds for a single Promptfoo evaluation.
        max_retries: Number of retries on transient failures.
        report_output_dir: Directory where generated reports are saved.
        report_formats: Default output formats (``json``, ``html``, ``markdown``).
        owasp_config_dir: Directory containing OWASP config YAMLs.
        quick_start_config_dir: Directory containing quick-start configs.
        data_dir: Directory containing ``vulnerabilities.json`` and
                  ``attack-patterns.yml``.
    """

    target: str = ""
    provider: str = "openai:chat:gpt-4o"
    promptfoo_path: Optional[str] = None
    timeout_sec: int = 600
    max_retries: int = 3
    report_output_dir: str = "./security-results"
    report_formats: list[str] = field(default_factory=lambda: ["json", "html"])
    owasp_config_dir: str = ""
    quick_start_config_dir: str = ""
    data_dir: str = ""

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "Settings":
        """Create settings populated from ``SECURITY_*`` environment variables.

        Environment variables recognised:
            ``SECURITY_TARGET``
            ``SECURITY_PROVIDER``
            ``SECURITY_PROMPTFOO_PATH``
            ``SECURITY_TIMEOUT``
            ``SECURITY_MAX_RETRIES``
            ``SECURITY_REPORT_DIR``
        """
        return cls(
            target=os.getenv("SECURITY_TARGET", ""),
            provider=os.getenv("SECURITY_PROVIDER", "openai:chat:gpt-4o"),
            promptfoo_path=os.getenv("SECURITY_PROMPTFOO_PATH") or None,
            timeout_sec=int(os.getenv("SECURITY_TIMEOUT", "600")),
            max_retries=int(os.getenv("SECURITY_MAX_RETRIES", "3")),
            report_output_dir=os.getenv("SECURITY_REPORT_DIR", "./security-results"),
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Settings":
        """Load settings from a YAML configuration file.

        Args:
            path: Path to the YAML file.

        Returns:
            A :class:`Settings` instance.

        Raises:
            ValueError: If the YAML file cannot be parsed.
            FileNotFoundError: If the file does not exist.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Settings file not found: {p}")
        if yaml is None:
            raise ImportError("PyYAML is required. Install with: pip install pyyaml")
        with p.open("r", encoding="utf-8") as fh:
            raw: Dict[str, Any] = yaml.safe_load(fh) or {}
        # Filter to known dataclass fields
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in raw.items() if k in known}
        return cls(**filtered)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize settings to a plain dictionary."""
        return {
            "target": self.target,
            "provider": self.provider,
            "promptfoo_path": self.promptfoo_path,
            "timeout_sec": self.timeout_sec,
            "max_retries": self.max_retries,
            "report_output_dir": self.report_output_dir,
            "report_formats": self.report_formats,
        }

    # ------------------------------------------------------------------
    # Internal path resolution (used by other modules)
    # ------------------------------------------------------------------

    def _resolve_owasp_dir(self) -> Path:
        """Return path to OWASP configs, resolving from package data if unset."""
        if self.owasp_config_dir:
            return Path(self.owasp_config_dir)
        # Fall back to bundled configs shipped inside the package
        base = Path(__file__).resolve().parent / "configs" / "owasp"
        if base.is_dir():
            return base
        return Path("configs") / "owasp"

    def _resolve_quick_start_dir(self) -> Path:
        """Return path to quick-start configs."""
        if self.quick_start_config_dir:
            return Path(self.quick_start_config_dir)
        base = Path(__file__).resolve().parent / "configs" / "quick-start"
        if base.is_dir():
            return base
        return Path("configs") / "quick-start"

    def _resolve_data_dir(self) -> Path:
        """Return path to data files (vulnerabilities, attack patterns)."""
        if self.data_dir:
            return Path(self.data_dir)
        base = Path(__file__).resolve().parent / "data"
        if base.is_dir():
            return base
        return Path("data")
