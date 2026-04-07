from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "ODIN_"}

    anthropic_api_key: str = ""
    llm_model: str = "glm-4.7"
    llm_api_key: str = ""
    llm_base_url: str = "https://open.bigmodel.cn/api/paas/v4"
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

    # GitHub webhook integration
    github_token: str = ""
    github_webhook_secret: str = ""
    webhook_max_file_bytes: int = 100_000

    # GitHub App integration (one-click install flow)
    github_app_id: str = ""
    github_app_client_id: str = ""
    github_app_client_secret: str = ""
    github_app_private_key: str = ""  # PEM content, newlines as \n
    github_app_webhook_secret: str = ""

    # MCP server
    mcp_enabled: bool = True

    # Deployment
    environment: str = "development"
    port: int = 8000

    # Provider configuration
    llm_provider: str = "default"  # "lmstudio" | "openrouter" | "openai" | "ollama" | "default"
    lmstudio_base_url: str = "http://localhost:1234/v1"
    lmstudio_model: str = "local-model"
    openrouter_api_key: str = ""
    openrouter_model: str = "anthropic/claude-sonnet-4-5"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    ollama_base_url: str = "http://localhost:11434/v1"
    ollama_model: str = "qwen2.5-coder"

    # Rules engine
    rules_enabled: bool = True
    rules_complexity_threshold: int = 10
    rules_function_length_threshold: int = 50
    rules_nesting_depth_threshold: int = 4

    # Dataflow-guided LLM triage (LLift/INFERROI architecture)
    # Enable to run intra-procedural taint analysis + LLM exploitability judgment
    dataflow_enabled: bool = True
    dataflow_max_candidates: int = 20  # cap per file before LLM spend
    dataflow_triage_confidence_floor: float = 0.6  # min confidence to surface finding

    # Minimum confidence threshold — findings below this are suppressed (0.0 = show all)
    min_confidence: float = 0.0

    # Review store TTL (seconds)
    review_store_ttl: int = 2_592_000  # 30 days


settings = Settings()
