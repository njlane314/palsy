from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PALSY_", env_file=".env", extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8080
    state_dir: Path = Field(default=Path("./state"))
    upstream_pypi: str = "https://pypi.org"
    upstream_npm: str = "https://registry.npmjs.org"
    npm_token: str | None = None
    oci_username: str | None = None
    oci_password: str | None = None
    policy_file: Path | None = None
    signing_key_file: Path | None = None
    sandbox_backend: Literal["none", "docker"] = "none"
    sandbox_timeout_seconds: int = 20
    max_artifact_bytes: int = 200 * 1024 * 1024
    http_timeout_seconds: float = 30.0
    allow_insecure_upstream_http: bool = False
    require_api_token: bool = True
    api_token: str | None = None
    log_level: str = "INFO"

    @property
    def db_path(self) -> Path:
        return self.state_dir / "palsy.db"

    @property
    def mirror_dir(self) -> Path:
        return self.state_dir / "mirror"

    @property
    def quarantine_dir(self) -> Path:
        return self.state_dir / "quarantine"

    @property
    def key_path(self) -> Path:
        return self.signing_key_file or (self.state_dir / "keys" / "ed25519_private.pem")

    def ensure_dirs(self) -> None:
        for path in [self.state_dir, self.mirror_dir, self.quarantine_dir, self.key_path.parent]:
            path.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_dirs()
    return settings
