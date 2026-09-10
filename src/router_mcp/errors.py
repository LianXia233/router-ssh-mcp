"""结构化错误模型。

所有工具在失败时返回统一结构，便于上层模型解析：

    {
      "ok": false,
      "tool": "service_restart",
      "host": "192.168.1.1",
      "error": {
        "code": "SERVICE_NOT_FOUND",
        "message": "...",
        "hint": "...",
        "details": {...}
      }
    }
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ErrorCode(str, Enum):
    """错误码枚举，取值稳定，供上层做条件分支。"""

    CONFIG_ERROR = "CONFIG_ERROR"
    INVALID_INPUT = "INVALID_INPUT"
    BLOCKED_COMMAND = "BLOCKED_COMMAND"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    AUTH_FAILED = "AUTH_FAILED"
    HOST_KEY_UNVERIFIED = "HOST_KEY_UNVERIFIED"
    COMMAND_TIMEOUT = "COMMAND_TIMEOUT"
    COMMAND_FAILED = "COMMAND_FAILED"
    SERVICE_NOT_FOUND = "SERVICE_NOT_FOUND"
    UNSUPPORTED_ACTION = "UNSUPPORTED_ACTION"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    CONFIRMATION_REQUIRED = "CONFIRMATION_REQUIRED"
    SHELL_DISABLED = "SHELL_DISABLED"
    BACKEND_ERROR = "BACKEND_ERROR"


@dataclass(frozen=True)
class ToolError(Exception):
    """工具层的可预期错误，携带错误码与修复建议。"""

    code: ErrorCode
    message: str
    hint: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code.value,
            "message": self.message,
        }
        if self.hint:
            payload["hint"] = self.hint
        if self.details:
            payload["details"] = self.details
        return payload

    def __str__(self) -> str:  # pragma: no cover - 便于日志排查
        base = f"[{self.code.value}] {self.message}"
        return f"{base} (hint: {self.hint})" if self.hint else base
