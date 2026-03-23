"""Entry point for running Odin as an MCP server over stdio transport.

Usage:
    python -m app.mcp.stdio_runner

Configure in Claude Code (~/.claude/claude_desktop_config.json):
    {
      "mcpServers": {
        "odin": {
          "command": "python",
          "args": ["-m", "app.mcp.stdio_runner"],
          "cwd": "/path/to/odin/backend",
          "env": {
            "ODIN_ANTHROPIC_API_KEY": "sk-ant-..."
          }
        }
      }
    }
"""
from __future__ import annotations

import asyncio

import structlog

# Ensure structlog is configured before any logging occurs
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
)


def main() -> None:
    from app.mcp.server import mcp

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
