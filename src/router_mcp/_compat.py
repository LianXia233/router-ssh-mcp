"""MCP SDK 版本兼容层。

mcp 2.x 把 ``FastMCP`` 更名为 ``MCPServer`` 并调整了部分参数名；
本模块统一暴露入口，使代码同时兼容 1.x 与 2.x。
"""

from __future__ import annotations

from typing import Any

try:  # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer as _Server  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - mcp < 2.0
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[assignment]

try:
    from mcp.types import ToolAnnotations  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover
    ToolAnnotations = None  # type: ignore[assignment]

MCPServer = _Server


def annotations(
    *,
    read_only: bool,
    destructive: bool,
    idempotent: bool,
    title: str | None = None,
) -> Any:
    """构建工具注解，屏蔽 1.x（camelCase）与 2.x（snake_case）字段差异。"""
    if ToolAnnotations is None:
        return None
    candidates = (
        {
            "read_only_hint": read_only,
            "destructive_hint": destructive,
            "idempotent_hint": idempotent,
        },
        {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": idempotent,
        },
    )
    last_error: Exception | None = None
    for payload in candidates:
        try:
            payload = dict(payload)
            if title:
                payload["title"] = title
            return ToolAnnotations(**payload)
        except Exception as exc:  # noqa: BLE001 - 兼容探测
            last_error = exc
    raise RuntimeError(f"无法构造 ToolAnnotations: {last_error}")


READ_ONLY = {"read_only": True, "destructive": False, "idempotent": True}
WRITE_START = {"read_only": False, "destructive": False, "idempotent": True}
WRITE_STOP = {"read_only": False, "destructive": True, "idempotent": True}
WRITE_RESTART = {"read_only": False, "destructive": True, "idempotent": False}

__all__ = ["MCPServer", "annotations", "READ_ONLY", "WRITE_START", "WRITE_STOP", "WRITE_RESTART"]
