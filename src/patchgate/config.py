"""Configuration from environment variables (optionally loaded from a local .env file)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


class ConfigError(RuntimeError):
    """Configuration is missing or invalid; the message says how to fix it."""


def _int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        v = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if not lo <= v <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}, got {v}")
    return v


@dataclass(frozen=True)
class Settings:
    gemini_api_key: str | None
    gemini_model: str
    gemini_timeout_s: int
    gemini_max_retries: int
    gemini_rpm: int
    gemini_max_backoff_s: int
    max_llm_calls: int
    max_attempts: int
    db_path: Path
    redact: bool

    @property
    def gemini_configured(self) -> bool:
        return bool(self.gemini_api_key)

    def require_gemini(self) -> str:
        if not self.gemini_api_key:
            raise ConfigError(
                "GEMINI_API_KEY is not set. Create a key at https://aistudio.google.com/apikey, then copy "
                ".env.example to .env and set GEMINI_API_KEY=..., or use the 'template' / 'simulated' proposer."
            )
        return self.gemini_api_key


def load_settings(env_file: str | None = ".env") -> Settings:
    if env_file and Path(env_file).exists():
        load_dotenv(env_file, override=False)
    key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or None
    if key is not None and (key.strip() == "" or key.strip().lower().startswith("your-")):
        key = None
    model = (os.getenv("GEMINI_MODEL") or "gemini-2.5-flash").strip()
    return Settings(
        gemini_api_key=key.strip() if key else None,
        gemini_model=model,
        gemini_timeout_s=_int("GEMINI_TIMEOUT_S", 60, 5, 600),
        gemini_max_retries=_int("GEMINI_MAX_RETRIES", 3, 0, 6),
        gemini_rpm=_int("GEMINI_RPM", 0, 0, 10_000),
        gemini_max_backoff_s=_int("GEMINI_MAX_BACKOFF_S", 65, 1, 300),
        max_llm_calls=_int("PATCHGATE_MAX_LLM_CALLS", 30, 1, 1000),
        max_attempts=_int("PATCHGATE_MAX_ATTEMPTS", 3, 1, 6),
        db_path=Path(os.getenv("PATCHGATE_DB") or "data/patchgate.db"),
        redact=(os.getenv("PATCHGATE_REDACT", "true").strip().lower() not in ("0", "false", "no")),
    )
