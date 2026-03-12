"""Configuration module for Freddy."""

from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv

    ENV_PATH = Path(__file__).parent / ".env"
    if ENV_PATH.exists():
        load_dotenv(ENV_PATH)
except ImportError:
    pass

BASE_DIR = Path(__file__).parent.resolve()
RUNTIME_DIR = BASE_DIR / ".freddy"
KNOWLEDGE_DIR = BASE_DIR / "knowledge"
VULNERABILITY_DIR = BASE_DIR / "vulnerabilities"
VECTOR_DB_DIR = RUNTIME_DIR / "vector_store"
MEMORY_DB_PATH = RUNTIME_DIR / "freddy_memory.db"
SYSTEM_PROMPT_PATH = BASE_DIR / "prompts" / "system_prompt.txt"

API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022").strip()
MAX_TOKENS = int(os.environ.get("ANTHROPIC_MAX_TOKENS", "4096"))
EMBEDDING_MODEL = os.environ.get("FREDDY_EMBEDDING_MODEL", "all-MiniLM-L6-v2").strip()


def ensure_runtime_directories() -> None:
    """Create Freddy runtime directories if missing."""
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    VECTOR_DB_DIR.mkdir(parents=True, exist_ok=True)


def validate_config() -> None:
    """Validate configuration needed for model-backed analysis commands."""
    ensure_runtime_directories()

    if not API_KEY:
        print("\n[!] ERROR: ANTHROPIC_API_KEY environment variable is not set.\n")
        sys.exit(1)

    if not SYSTEM_PROMPT_PATH.exists():
        print(f"\n[!] ERROR: System prompt not found at {SYSTEM_PROMPT_PATH}\n")
        sys.exit(1)


def validate_paths() -> None:
    """Validate non-secret Freddy runtime and content paths."""
    ensure_runtime_directories()
    missing = [path for path in (KNOWLEDGE_DIR, VULNERABILITY_DIR, SYSTEM_PROMPT_PATH.parent) if not path.exists()]
    if missing:
        print("\n[!] ERROR: Freddy content directories are missing:\n")
        for path in missing:
            print(f"    - {path}")
        print()
        sys.exit(1)


def get_config() -> dict:
    """Return the current configuration as a dictionary."""
    ensure_runtime_directories()
    return {
        "api_key_set": bool(API_KEY),
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "system_prompt_path": str(SYSTEM_PROMPT_PATH),
        "knowledge_dir": str(KNOWLEDGE_DIR),
        "vulnerability_dir": str(VULNERABILITY_DIR),
        "vector_db_dir": str(VECTOR_DB_DIR),
        "memory_db_path": str(MEMORY_DB_PATH),
        "embedding_model": EMBEDDING_MODEL,
    }
