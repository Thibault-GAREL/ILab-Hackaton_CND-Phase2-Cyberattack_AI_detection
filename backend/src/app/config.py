"""Configuration backend Phase 2 via Pydantic Settings."""

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    env: Literal["development", "production", "test"] = Field(default="development")
    debug: bool = Field(default=False)

    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8080)
    api_version: str = Field(default="2.0.0")

    cors_origins: str = Field(default="")

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(default="INFO")

    detections_json_path: str = Field(default="detections.json")

    # Propagés vers le sous-process `python -m pipeline` (voir pipeline_bridge._pipeline_env).
    # Sur ECS : définir surtout OPENSEARCH_BASIC_PASSWORD (secret / variable de tâche).
    opensearch_auth: str | None = Field(default=None)
    opensearch_basic_user: str | None = Field(default=None)
    opensearch_basic_password: str | None = Field(default=None)
    opensearch_host: str | None = Field(default=None)

    # Autorise POST pipeline avec --submit (soumission live API scoring). Désactivé par défaut en prod.
    pipeline_allow_submit: bool = Field(default=False)

    @property
    def cors_origins_list(self) -> list[str]:
        if not self.cors_origins:
            return []
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
