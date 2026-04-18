"""Load per-project Odin configuration from .odin.yml / .odin.yaml.

Configuration is discovered by walking upward from the current working directory
(or a given root) until a config file is found or the filesystem root is reached.
All fields are optional — missing config is equivalent to an empty config object.

Example .odin.yml:
    min_severity: low
    fail_on: high
    min_confidence: 0.0

    quality_gate:
      min_score: 70
      max_critical: 0
      max_high: 5

    ignore:
      - rule: "eval() usage"
        path: "scripts/"
        reason: "build-time only"

    exclude:
      - "node_modules/"
      - "migrations/"
      - "*.min.js"
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

_CONFIG_NAMES = (".odin.yml", ".odin.yaml")


@dataclass
class QualityGate:
    min_score: int = 0  # fail if overall_score < min_score (0 = disabled)
    max_critical: int = -1  # fail if critical_count > max_critical (-1 = disabled)
    max_high: int = -1  # fail if high_count > max_high (-1 = disabled)

    @classmethod
    def from_dict(cls, d: dict) -> QualityGate:  # type: ignore[type-arg]
        return cls(
            min_score=int(d.get("min_score", 0)),
            max_critical=int(d.get("max_critical", -1)),
            max_high=int(d.get("max_high", -1)),
        )

    def is_active(self) -> bool:
        return self.min_score > 0 or self.max_critical >= 0 or self.max_high >= 0


@dataclass
class IgnoreRule:
    rule: str  # substring match against finding title
    path: str = ""  # glob pattern against file path (empty = all files)
    reason: str = ""


@dataclass
class OdinConfig:
    min_severity: str = "low"
    fail_on: str = "high"
    min_confidence: float = 0.0
    max_findings: int = 0  # 0 = unlimited; otherwise keep top-N by (severity, confidence)
    quality_gate: QualityGate = field(default_factory=QualityGate)
    ignore: list[IgnoreRule] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    # Path to the config file that was loaded (None if defaults)
    config_path: Path | None = None

    def is_ignored(self, title: str, filepath: str) -> bool:
        """Return True if a finding with this title on this path should be ignored."""
        for rule in self.ignore:
            if rule.rule.lower() not in title.lower():
                continue
            if not rule.path or fnmatch.fnmatch(filepath, f"*{rule.path}*"):
                return True
        return False

    def is_excluded(self, filepath: str) -> bool:
        """Return True if this file path matches any exclude pattern."""
        return any(fnmatch.fnmatch(filepath, f"*{pattern}*") for pattern in self.exclude)


def _parse_config(data: dict, config_path: Path) -> OdinConfig:  # type: ignore[type-arg]
    ignore = [
        IgnoreRule(
            rule=str(item.get("rule", "")),
            path=str(item.get("path", "")),
            reason=str(item.get("reason", "")),
        )
        for item in data.get("ignore", [])
        if isinstance(item, dict) and item.get("rule")
    ]
    qg_data = data.get("quality_gate", {})
    return OdinConfig(
        min_severity=str(data.get("min_severity", "low")),
        fail_on=str(data.get("fail_on", "high")),
        min_confidence=float(data.get("min_confidence", 0.0)),
        max_findings=int(data.get("max_findings", 0) or 0),
        quality_gate=QualityGate.from_dict(qg_data) if isinstance(qg_data, dict) else QualityGate(),
        ignore=ignore,
        exclude=[str(e) for e in data.get("exclude", [])],
        config_path=config_path,
    )


def _load_yaml(path: Path) -> dict:  # type: ignore[type-arg]
    """Parse a YAML file. Falls back to a minimal hand-parser when PyYAML is absent."""
    try:
        import yaml  # type: ignore[import-untyped]

        with path.open(encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        pass

    # Minimal fallback: parse key: value lines (no nested YAML support)
    result: dict = {}  # type: ignore[type-arg]
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.rstrip()
            if line.startswith("#") or not line or line.startswith(" ") or line.startswith("\t"):
                continue
            if ":" in line:
                k, _, v = line.partition(":")
                result[k.strip()] = v.strip()
    return result


def find_config(root: Path | None = None) -> Path | None:
    """Walk up from *root* (default: cwd) to find the nearest .odin.yml / .odin.yaml."""
    current = (root or Path.cwd()).resolve()
    while True:
        for name in _CONFIG_NAMES:
            candidate = current / name
            if candidate.is_file():
                return candidate
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def load_config(root: Path | None = None) -> OdinConfig:
    """Load OdinConfig from the nearest .odin.yml, or return defaults if none found."""
    config_file = find_config(root)
    if config_file is None:
        return OdinConfig()
    try:
        data = _load_yaml(config_file)
        return _parse_config(data, config_file)
    except Exception:
        return OdinConfig()
