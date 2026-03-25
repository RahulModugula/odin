"""Registry for named LLM provider configurations."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.config import settings


@dataclass
class ProviderConfig:
    name: str
    base_url: str
    model: str
    api_key: str = field(default="")
    description: str = field(default="")


PRESET_PROVIDERS: dict[str, ProviderConfig] = {
    "lmstudio": ProviderConfig(
        name="lmstudio",
        base_url="http://localhost:1234/v1",
        model="local-model",
        api_key="lm-studio",
        description="LM Studio — local models, zero API cost",
    ),
    "openrouter": ProviderConfig(
        name="openrouter",
        base_url="https://openrouter.ai/api/v1",
        model="anthropic/claude-sonnet-4-5",
        api_key="",
        description="OpenRouter — BYOK, 100+ models",
    ),
    "openai": ProviderConfig(
        name="openai",
        base_url="https://api.openai.com/v1",
        model="gpt-4o-mini",
        api_key="",
        description="OpenAI API",
    ),
    "ollama": ProviderConfig(
        name="ollama",
        base_url="http://localhost:11434/v1",
        model="qwen2.5-coder",
        api_key="ollama",
        description="Ollama — local models",
    ),
}


def list_providers() -> list[ProviderConfig]:
    """Return all preset provider configurations."""
    return list(PRESET_PROVIDERS.values())


def get_provider(name: str) -> ProviderConfig | None:
    """Return a preset provider by name, or None if not found."""
    return PRESET_PROVIDERS.get(name)


def get_active_provider() -> ProviderConfig:
    """Return the currently active provider based on settings."""
    name = settings.llm_provider
    if name in PRESET_PROVIDERS:
        return PRESET_PROVIDERS[name]

    # custom / default
    return ProviderConfig(
        name="default",
        base_url=settings.llm_base_url,
        model=settings.llm_model,
        api_key=settings.llm_api_key or settings.anthropic_api_key,
        description="Custom / default provider",
    )
