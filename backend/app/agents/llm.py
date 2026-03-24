"""Shared LLM factory — returns a ChatOpenAI instance pointed at the configured provider."""

from __future__ import annotations

from langchain_openai import ChatOpenAI

from app.config import settings


def get_llm() -> ChatOpenAI:
    return ChatOpenAI(
        model=settings.llm_model,
        api_key=settings.llm_api_key or settings.anthropic_api_key,  # type: ignore[arg-type]
        base_url=settings.llm_base_url or None,
        temperature=0,
        max_tokens=4096,
    )
