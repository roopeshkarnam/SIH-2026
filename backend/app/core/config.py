from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Cryptographic Attribution System"
    app_version: str = "1.0.0"
    database_url: str
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 30
    storage_root: str = "storage"
    key_storage_path: str = "storage/keys"
    max_upload_size_mb: int = 100
    pqc_kem_algorithm: str = "ML-KEM-768"
    pqc_signature_algorithm: str = "ML-DSA-65"
    keystore_master_key: str
    ledger_enabled: bool = False
    fabric_gateway_url: str | None = None
    watermark_enabled: bool = True
    frontend_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    environment: str = "development"

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
