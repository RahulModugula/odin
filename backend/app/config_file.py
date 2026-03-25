"""Load and merge .odin.yaml / odin.yaml configuration files."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Pydantic model for the YAML config structure
# ---------------------------------------------------------------------------


class ProviderFileConfig(BaseModel):
    name: str = ""
    base_url: str = ""
    api_key: str = ""
    model: str = ""


class ReviewFileConfig(BaseModel):
    agents: list[str] = []
    severity_threshold: str = "low"
    max_findings: int = 50


class IgnoreFileConfig(BaseModel):
    paths: list[str] = []
    rules: list[str] = []


class QualityGateFileConfig(BaseModel):
    min_score: int = 0
    max_critical: int = 0
    max_high: int = 0
    block_on_fail: bool = False


class RulesFileConfig(BaseModel):
    enabled: bool = True
    complexity_threshold: int = 10
    function_length_threshold: int = 50
    nesting_depth_threshold: int = 4


class OdinConfigFile(BaseModel):
    provider: ProviderFileConfig = ProviderFileConfig()
    review: ReviewFileConfig = ReviewFileConfig()
    ignore: IgnoreFileConfig = IgnoreFileConfig()
    quality_gate: QualityGateFileConfig = QualityGateFileConfig()
    rules: RulesFileConfig = RulesFileConfig()


# ---------------------------------------------------------------------------
# Search and load logic
# ---------------------------------------------------------------------------

_SEARCH_PATHS = [
    Path("odin.yaml"),
    Path(".odin.yaml"),
    Path.home() / ".odin" / "config.yaml",
]


def _find_config_file() -> Path | None:
    # Env-var override takes top priority
    env_path = os.environ.get("ODIN_CONFIG_FILE")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p

    for candidate in _SEARCH_PATHS:
        if candidate.exists():
            return candidate

    return None


def load_config_file() -> OdinConfigFile | None:
    """Return a parsed OdinConfigFile if a config file exists, else None."""
    path = _find_config_file()
    if path is None:
        return None

    try:
        import yaml  # type: ignore[import-untyped]

        with path.open() as fh:
            raw: Any = yaml.safe_load(fh)

        if not isinstance(raw, dict):
            return None

        return OdinConfigFile.model_validate(raw)
    except Exception:
        # Never crash the application over a missing or malformed config file
        return None


def get_merged_config() -> dict[str, Any]:
    """Return a dict of provider settings merged from the YAML file.

    The caller (e.g. get_llm()) can use these overrides on top of the
    pydantic Settings values.  Keys mirror Settings field names.
    """
    cfg = load_config_file()
    if cfg is None:
        return {}

    merged: dict[str, Any] = {}
    p = cfg.provider

    if p.name:
        merged["llm_provider"] = p.name
    if p.base_url:
        merged["llm_base_url"] = p.base_url
    if p.api_key:
        merged["llm_api_key"] = p.api_key
    if p.model:
        merged["llm_model"] = p.model

    r = cfg.rules
    merged["rules_enabled"] = r.enabled
    merged["rules_complexity_threshold"] = r.complexity_threshold
    merged["rules_function_length_threshold"] = r.function_length_threshold
    merged["rules_nesting_depth_threshold"] = r.nesting_depth_threshold

    return merged
