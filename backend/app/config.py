from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "ODIN_"}

    anthropic_api_key: str = ""
    llm_model: str = "claude-sonnet-4-20250514"
    redis_url: str = "redis://localhost:6379/0"
    log_level: str = "INFO"
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]


settings = Settings()
