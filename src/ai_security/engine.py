"""
Promptfoo CLI Engine — subprocess wrapper for Promptfoo evaluation.

This module runs Promptfoo as an external CLI tool (``promptfoo eval``,
``promptfoo redteam``) so the security framework acts as the *brain*
(configuration, result parsing, compliance) rather than the *muscle*
(the actual attack/evaluation engine).

Usage::

    engine = PromptfooEngine()
    ok, msg = engine.check_dependencies()
    if ok:
        rc, stdout, stderr = engine.eval("configs/llm01.yml")
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class PromptfooEvalResult:
    """Parsed result of a ``promptfoo eval`` run.

    Attributes:
        return_code: Subprocess exit code (0 = success).
        stdout: Full stdout text.
        stderr: Full stderr text.
        parsed: Parsed JSON data if available.
    """

    return_code: int = 0
    stdout: str = ""
    stderr: str = ""
    parsed: Optional[Dict[str, Any]] = None
    config_name: str = ""
    error: str = ""

    @property
    def success(self) -> bool:
        """``True`` if the subprocess exited with code 0."""
        return self.return_code == 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "return_code": self.return_code,
            "success": self.success,
            "config_name": self.config_name,
            "error": self.error,
            "stderr": self.stderr[:500],
        }


@dataclass
class PromptfooRedteamResult:
    """Parsed result of a ``promptfoo redteam`` run.

    Attributes:
        return_code: Subprocess exit code.
        stdout: Full stdout text.
        stderr: Full stderr text.
        parsed: Parsed JSON data if available.
    """

    return_code: int = -1
    stdout: str = ""
    stderr: str = ""
    parsed: Optional[Dict[str, Any]] = None
    error: str = ""

    @property
    def success(self) -> bool:
        """``True`` if the subprocess exited with code 0."""
        return self.return_code == 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "return_code": self.return_code,
            "success": self.success,
            "error": self.error,
            "stderr": self.stderr[:500],
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class PromptfooEngine:
    """CLI wrapper for Promptfoo security evaluation.

    Invokes ``promptfoo eval`` and ``promptfoo redteam`` as subprocesses,
    collects structured output, and returns parsed result objects.

    Args:
        timeout: Maximum seconds to wait for a subprocess call.
        promptfoo_path: Explicit path to the binary (overrides PATH lookup).
    """

    def __init__(
        self,
        timeout: int = 600,
        promptfoo_path: Optional[str] = None,
    ) -> None:
        self._timeout = timeout
        self._promptfoo_path = promptfoo_path
        self._last_eval_result: Optional[PromptfooEvalResult] = None
        self._last_rt_result: Optional[PromptfooRedteamResult] = None

    # ------------------------------------------------------------------
    # Dependency check
    # ------------------------------------------------------------------

    def check_dependencies(self) -> Tuple[bool, str]:
        """Verify that the ``promptfoo`` CLI is available.

        Returns:
            ``(True, message)`` if available, ``(False, error_message)``.
        """
        bin_path = self._find_promptfoo()
        if bin_path is None:
            return False, (
                "Promptfoo CLI not found on PATH.\n"
                "Install it with:  npm install -g promptfoo\n"
                "Or set the PROMPTFOO_BIN environment variable."
            )
        try:
            result = subprocess.run(
                [bin_path, "--version"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            version_output = (result.stdout.strip() or result.stderr.strip() or "unknown")
            return True, f"Promptfoo found at {bin_path} ({version_output})"
        except (subprocess.TimeoutExpired, OSError) as exc:
            return False, f"Promptfoo found but could not execute: {exc}"

    # ------------------------------------------------------------------
    # Binary resolution
    # ------------------------------------------------------------------

    def _find_promptfoo(self) -> Optional[str]:
        """Locate the ``promptfoo`` binary.

        Search order:
        1. Instance-level override (``promptfoo_path``)
        2. ``PROMPTFOO_BIN`` environment variable
        3. System PATH (``shutil.which``)
        4. Common npm global bin locations
        """
        # 1. Instance override
        if self._promptfoo_path:
            p = Path(self._promptfoo_path)
            if p.is_file():
                return str(p)

        # 2. Environment
        env_path = os.environ.get("PROMPTFOO_BIN")
        if env_path:
            p = Path(env_path)
            if p.is_file():
                return str(p)

        # 3. PATH
        binary = shutil.which("promptfoo")
        if binary:
            return binary

        # 4. Common locations
        candidates = [
            "/usr/local/bin/promptfoo",
            "/usr/bin/promptfoo",
            os.path.expanduser("~/.npm-global/bin/promptfoo"),
            os.path.expanduser("~/.local/lib/node_modules/.bin/promptfoo"),
        ]
        for c in candidates:
            cp = Path(c)
            if cp.is_file() and os.access(cp, os.X_OK):
                return str(cp)

        return None

    # ------------------------------------------------------------------
    # Public: eval
    # ------------------------------------------------------------------

    def eval(
        self,
        config_path: str | Path,
        *,
        extra_args: Optional[List[str]] = None,
        output_path: Optional[str | Path] = None,
        timeout: Optional[int] = None,
    ) -> PromptfooEvalResult:
        """Run ``promptfoo eval -c <config>`` via subprocess.

        Args:
            config_path: Path to the YAML config to evaluate.
            extra_args: Additional CLI arguments.
            output_path: File to write JSON results to.
            timeout: Per-run timeout override.

        Returns:
            :class:`PromptfooEvalResult` with parsed output.
        """
        promptfoo_bin = self._find_promptfoo()
        if promptfoo_bin is None:
            return PromptfooEvalResult(
                return_code=-1,
                stderr="promptfoo not installed or not on PATH",
                config_name=str(config_path),
                error="engine_not_found",
            )

        timeout = timeout or self._timeout
        extra_args = extra_args or []

        cmd: List[str] = [promptfoo_bin, "eval", "-c", str(config_path)]
        if output_path:
            cmd += ["-o", str(output_path)]
        # Force JSON output for parseability
        if "--output" not in extra_args:
            cmd += ["--output", "json"]
        cmd.extend(extra_args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            err_result = PromptfooEvalResult(
                return_code=-1,
                stdout=str(exc.stdout or ""),
                stderr=f"Timeout after {timeout}s: {exc.stderr or ''}",
                config_name=str(config_path),
                error="timeout",
            )
            self._last_eval_result = err_result
            return err_result
        except OSError as exc:
            err_result = PromptfooEvalResult(
                return_code=-1,
                stdout="",
                stderr=str(exc),
                config_name=str(config_path),
                error="os_error",
            )
            self._last_eval_result = err_result
            return err_result

        # Parse JSON output if present
        parsed = None
        if output_path and Path(output_path).exists():
            try:
                parsed = json.loads(Path(output_path).read_text(encoding="utf-8"))
            except (json.JSONDecodeError, IOError):
                pass

        eval_result = PromptfooEvalResult(
            return_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            parsed=parsed,
            config_name=str(Path(config_path).stem),
        )
        self._last_eval_result = eval_result
        return eval_result

    # ------------------------------------------------------------------
    # Public: redteam
    # ------------------------------------------------------------------

    def redteam(
        self,
        *,
        config_path: Optional[str | Path] = None,
        strategy: str = "default",
        extra_args: Optional[List[str]] = None,
        timeout: Optional[int] = None,
    ) -> PromptfooRedteamResult:
        """Run ``promptfoo redteam`` via subprocess.

        Args:
            config_path: Optional config file for the redteam run.
            strategy: Attack strategy name.
            extra_args: Additional CLI arguments.
            timeout: Per-run timeout override.

        Returns:
            :class:`PromptfooRedteamResult` with parsed output.
        """
        promptfoo_bin = self._find_promptfoo()
        if promptfoo_bin is None:
            return PromptfooRedteamResult(
                return_code=-1,
                stderr="promptfoo not installed or not on PATH",
                error="engine_not_found",
            )

        timeout = timeout or self._timeout
        extra_args = extra_args or []

        cmd: List[str] = [promptfoo_bin, "redteam", "generate"]
        if config_path:
            cmd += ["-c", str(config_path)]
        if "--strategy" not in " ".join(extra_args):
            cmd += ["--strategy", strategy]
        cmd.extend(extra_args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            err_result = PromptfooRedteamResult(
                return_code=-1,
                stdout=str(exc.stdout or ""),
                stderr=f"Timeout after {timeout}s: {exc.stderr or ''}",
                error="timeout",
            )
            self._last_rt_result = err_result
            return err_result
        except OSError as exc:
            err_result = PromptfooRedteamResult(
                return_code=-1,
                stdout="",
                stderr=str(exc),
                error="os_error",
            )
            self._last_rt_result = err_result
            return err_result

        # Attempt to parse JSON
        parsed = None
        try:
            parsed = json.loads(result.stdout)
        except (json.JSONDecodeError, TypeError):
            pass

        rt_result = PromptfooRedteamResult(
            return_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            parsed=parsed,
        )
        self._last_rt_result = rt_result
        return rt_result

    # ------------------------------------------------------------------
    # Results access
    # ------------------------------------------------------------------

    def get_last_eval_result(self) -> Optional[PromptfooEvalResult]:
        """Return the result from the most recent ``eval()`` call."""
        return self._last_eval_result

    def get_last_redteam_result(self) -> Optional[PromptfooRedteamResult]:
        """Return the result from the most recent ``redteam()`` call."""
        return self._last_rt_result
