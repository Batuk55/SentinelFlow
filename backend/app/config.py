"""Application settings loaded from environment variables (and an optional .env file)."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = (
        "postgresql+psycopg://sentinel:sentinel_dev_password@localhost:5434/sentinelflow"
    )
    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    detection_rules_path: str = ""  # empty -> use bundled app/detection_rules.json

    # LLM settings (used by the RAG service in Phase 4)
    llm_provider: str = "gemini"  # "gemini" or "anthropic"
    gemini_api_key: str = ""
    anthropic_api_key: str = ""
    llm_model: str = ""  # empty -> provider default (see services/llm/base.py)

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
