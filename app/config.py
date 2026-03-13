from typing import Optional

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Configuration/settings loaded from environment or .env file."""

    # API keys
    virustotal_api_key: Optional[str] = Field("", env="VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: Optional[str] = Field("", env="ABUSEIPDB_API_KEY")
    google_search_api_key: Optional[str] = Field("", env="GOOGLE_SEARCH_API_KEY")
    google_search_cx: Optional[str] = Field("", env="GOOGLE_SEARCH_CX")

    # External service endpoints
    ipapi_url: AnyHttpUrl = Field("http://ip-api.com/json/", env="IPAPI_URL")

    # operational flags
    environment: str = Field("development", env="ENVIRONMENT")
    max_upload_size: int = Field(5 * 1024 * 1024, env="MAX_UPLOAD_SIZE")  # 5MB limit

    # local caching
    # a JSON file storing previous VirusTotal results to avoid repeated API queries
    hash_cache_path: str = Field("hash_cache.json", env="HASH_CACHE_PATH")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# create a singleton instance that can be imported elsewhere
settings = Settings()  


def get_settings() -> Settings:
    """FastAPI dependency for retrieving application settings."""
    return settings
