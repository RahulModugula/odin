from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "ODIN_"}

    anthropic_api_key: str = ""
    llm_model: str = "claude-sonnet-4-20250514"
    redis_url: str = "redis://localhost:6379/0"
    log_level: str = "INFO"
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Langfuse observability
    langfuse_enabled: bool = False
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""
    langfuse_host: str = "https://cloud.langfuse.com"

    # Graph RAG
    graph_rag_enabled: bool = False
    memgraph_uri: str = "bolt://localhost:7687"
    memgraph_auth: str | None = None

    # MCP server
    mcp_enabled: bool = True

    # Deployment
    environment: str = "development"
    port: int = 8000


settings = Settings()
