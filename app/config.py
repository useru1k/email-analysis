from typing import Optional

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration/settings loaded from environment or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # API keys
    virustotal_api_key: Optional[str] = Field("")
    abuseipdb_api_key: Optional[str] = Field("")
    google_search_api_key: Optional[str] = Field("")
    google_search_cx: Optional[str] = Field("")

    # External service endpoints
    ipapi_url: AnyHttpUrl = Field("http://ip-api.com/json/")

    # operational flags
    environment: str = Field("development")
    max_upload_size: int = Field(5 * 1024 * 1024)  # 5MB limit

    # local caching
    # a JSON file storing previous VirusTotal results to avoid repeated API queries
    hash_cache_path: str = Field("hash_cache.json")


# create a singleton instance that can be imported elsewhere
settings = Settings()


def get_settings() -> Settings:
    """FastAPI dependency for retrieving application settings."""
    return settings
