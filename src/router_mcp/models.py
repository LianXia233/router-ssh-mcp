"""MCP 工具的返回模型（pydantic），保证结构化输出可被上层模型直接解析。"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ErrorPayload(BaseModel):
    """错误详情。"""

    code: str = Field(description="稳定错误码，例如 SERVICE_NOT_FOUND / AUTH_FAILED")
    message: str = Field(description="人类可读的错误描述")
    hint: str = Field(default="", description="修复建议")
    details: dict[str, Any] = Field(default_factory=dict, description="结构化上下文")


class ServiceEntry(BaseModel):
    """单个服务的状态快照。"""

    name: str
    running: bool | None = Field(default=None, description="是否在运行；None 表示无法判定")
    enabled: bool | None = Field(default=None, description="是否开机自启")
    pid: int | None = Field(default=None, description="主进程 PID")
    started_at: str | None = Field(default=None, description="启动时间（本地时区字符串或 systemd 原始时间戳）")
    description: str | None = Field(default=None, description="服务描述或启动命令")
    source: str = Field(default="unknown", description="状态来源：procd / init.d / systemd / sysvinit")


class ServiceListData(BaseModel):
    services: list[ServiceEntry]
    count: int
    running_count: int = 0
    init_system: str
    host: str
    warnings: list[str] = Field(default_factory=list)


class ServiceStatusData(BaseModel):
    service: ServiceEntry
    checked_at: str = Field(description="查询时间（本地时区 ISO8601）")


class ServiceActionData(BaseModel):
    name: str
    action: str
    exit_status: int
    command: list[str] = Field(description="实际下发的 argv（未经过 shell）")
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    state_before: ServiceEntry | None = None
    state_after: ServiceEntry | None = None


class ServiceLogsData(BaseModel):
    name: str
    requested_lines: int
    returned_lines: int
    source: str = Field(description="日志来源：logread / journalctl / 文件")
    command: list[str]
    truncated: bool = False
    lines: list[str]


class RouterInfoData(BaseModel):
    host: str
    port: int
    username: str
    backend: str
    capability: str = Field(
        description="连接器能力标识，固定为 ssh-router-management，供上层软件识别其本质"
    )
    ssh: dict[str, Any] = Field(default_factory=dict, description="连接健康信息")
    device: dict[str, Any] = Field(default_factory=dict, description="设备与系统信息")
    security: dict[str, Any] = Field(default_factory=dict, description="当前生效的安全策略")
    limits: dict[str, Any] = Field(default_factory=dict, description="超时与重试阈值")
    warnings: list[str] = Field(default_factory=list, description="需要注意的提示信息")


class ShellData(BaseModel):
    """shell 命令执行结果（高危能力）。"""

    raw_command: str = Field(description="实际执行的命令字符串（已通过校验，未改写）")
    exit_status: int = Field(description="远端 shell 退出码")
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    host: str = Field(description="目标设备地址")
    reused_connection: bool = False
    denied: bool = Field(default=False, description="是否因高危拦截被拒绝")
    confirmed: bool = Field(default=False, description="是否经过二次确认")
    warning: str | None = Field(default=None, description="风险提示（如以 root 执行）")


class ToolResult(BaseModel, Generic[T]):
    """所有工具统一的外层结构。"""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    tool: str
    host: str
    duration_ms: int = 0
    data: T | None = None
    error: ErrorPayload | None = None


class ServiceListResult(ToolResult[ServiceListData]):
    pass


class ServiceStatusResult(ToolResult[ServiceStatusData]):
    pass


class ServiceActionResult(ToolResult[ServiceActionData]):
    pass


class ServiceLogsResult(ToolResult[ServiceLogsData]):
    pass


class RouterInfoResult(ToolResult[RouterInfoData]):
    pass


class ShellResult(ToolResult[ShellData]):
    pass


class ErrorResult(ToolResult[None]):
    ok: bool = False


def error_result(
    tool: str,
    host: str,
    error: ErrorPayload,
    duration_ms: int = 0,
) -> ErrorResult:
    return ErrorResult(ok=False, tool=tool, host=host, duration_ms=duration_ms, error=error)


def payload_from_error(exc: Exception) -> ErrorPayload:
    """把异常转成结构化错误负载。"""
    from .errors import ToolError

    if isinstance(exc, ToolError):
        return ErrorPayload(**exc.to_payload())
    return ErrorPayload(
        code="INTERNAL_ERROR",
        message=f"{type(exc).__name__}: {exc}",
        hint="这是未预期的异常，请检查服务端日志",
    )
