"""Shared LLM factory — returns a ChatOpenAI instance pointed at the configured provider."""

from __future__ import annotations

from langchain_openai import ChatOpenAI

from app.config import settings


def get_llm(provider: str | None = None) -> ChatOpenAI:
    """Return configured LLM. *provider* overrides ``settings.llm_provider``."""
    active = provider or settings.llm_provider

    if active == "lmstudio":
        return ChatOpenAI(
            model=settings.lmstudio_model,
            api_key="lm-studio",  # type: ignore[arg-type]
            base_url=settings.lmstudio_base_url,
            temperature=0,
            max_tokens=4096,
        )

    if active == "openrouter":
        return ChatOpenAI(
            model=settings.openrouter_model,
            api_key=settings.openrouter_api_key or "...",  # type: ignore[arg-type]
            base_url=settings.openrouter_base_url,
            temperature=0,
            max_tokens=4096,
            default_headers={
                "HTTP-Referer": "https://github.com/odin-review/odin",
                "X-Title": "Odin Code Review",
            },
        )

    if active == "ollama":
        return ChatOpenAI(
            model=settings.ollama_model,
            api_key="ollama",  # type: ignore[arg-type]
            base_url=settings.ollama_base_url,
            temperature=0,
            max_tokens=4096,
        )

    # default / openai / custom
    return ChatOpenAI(
        model=settings.llm_model,
        api_key=settings.llm_api_key or settings.anthropic_api_key,  # type: ignore[arg-type]
        base_url=settings.llm_base_url or None,
        temperature=0,
        max_tokens=4096,
    )


async def test_provider(provider: str | None = None) -> bool:
    """Test provider connectivity with a trivial completion.

    Returns ``True`` if the provider responds, ``False`` otherwise.
    """
    try:
        llm = get_llm(provider)
        await llm.ainvoke([{"role": "user", "content": "reply with just 'ok'"}])
        return True
    except Exception:
        return False
