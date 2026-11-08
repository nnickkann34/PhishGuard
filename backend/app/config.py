"""
Application settings.

Every value can be overridden with an environment variable prefixed
PG_ (for example PG_ALLOWED_ORIGINS) or in backend/.env. Nothing secret
is hard-coded in the source.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_DIR = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PG_",
        env_file=BACKEND_DIR / ".env",
        extra="ignore",
    )

    # --- Web --------------------------------------------------------------
    # Only the front end's exact origin may call the API from a browser.
    allowed_origins: list[str] = ["http://localhost:5173"]

    # --- Input limits (security hygiene, section 2.3) ---------------------
    # Real URLs are far shorter; browsers and servers commonly cap at ~2 KB.
    max_url_length: int = Field(2048, ge=16, le=8192)
    # Largest request body accepted, checked before the body is parsed.
    max_body_bytes: int = Field(64 * 1024, ge=1024, le=100_000_000)
    # Most URLs accepted in one batch request.
    max_batch_urls: int = Field(50, ge=1, le=100_000)

    # --- Model ------------------------------------------------------------
    model_path: Path = BACKEND_DIR / "models" / "phishguard_xgb.json"
    metadata_path: Path = BACKEND_DIR / "models" / "model_metadata.json"
    # Expected SHA-256 of the model file. The server refuses to start if
    # the file on disk does not match (it may have been swapped).
    model_sha256_path: Path = BACKEND_DIR / "models" / "phishguard_xgb.json.sha256"

    # --- Denial-of-service defence (section 2.7, Advanced) ----------------
    # When false, inference runs inline in the event loop with no limits,
    # which is how the attack is demonstrated. Leave true in normal use.
    dos_protection: bool = True
    # Threads that run model inference.
    inference_workers: int = Field(2, ge=1, le=32)
    # Requests allowed to wait for a free worker; any more get HTTP 503.
    inference_queue: int = Field(8, ge=0, le=1000)
    # Longest a single request may spend in inference before HTTP 503.
    inference_timeout_seconds: float = Field(5.0, gt=0, le=60)

    # --- SQL injection defence (section 2.7, Intermediate) ----------------
    # When true, the history search uses a deliberately unsafe SQL string
    # so the attack can be demonstrated. Never enable outside the demo.
    insecure_sql_demo: bool = False

    # --- Detection-evasion defence (section 2.8) --------------------------
    # Normalise look-alike Unicode characters before features are built.
    normalise_homoglyphs: bool = True

    # --- Storage ----------------------------------------------------------
    database_url: str = f"sqlite:///{(BACKEND_DIR / 'data' / 'phishguard.db').as_posix()}"
    history_page_size: int = Field(100, ge=1, le=500)


@lru_cache
def get_settings() -> Settings:
    return Settings()
