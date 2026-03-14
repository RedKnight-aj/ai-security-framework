"""
Configuration management
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class Settings:
    """Security framework settings."""
    
    target: str = ""
    provider: str = "openai:gpt-4"
    max_attempts: int = 100
    threshold: float = 0.5
    
    # Promptfoo settings
    config_path: str = "./promptfoo"
    plugins: str = "default"
    
    # Report settings
    report_format: str = "json"
    report_path: str = "./security-results"
    
    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            target=os.getenv("SECURITY_TARGET", ""),
            provider=os.getenv("SECURITY_PROVIDER", "openai:gpt-4"),
            max_attempts=int(os.getenv("SECURITY_MAX_ATTEMPTS", "100")),
        )


__all__ = ["Settings"]
