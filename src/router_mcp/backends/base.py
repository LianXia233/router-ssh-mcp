"""服务后端抽象层：统一的数据结构与行为约定。"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

from ..commands import (
    CommandSpec,
    proc_pid_stat,
    read_file,
    uname as uname_cmd,
)
from ..errors import ErrorCode, ToolError
from ..programs import ProgramResolver
from ..ssh_pool import CommandResult

ActionName = Literal["start", "stop", "restart", "reload"]

CLK_TCK = 100  # Linux 用户态可见的时钟频率，用于把 /proc/<pid>/stat 的 tick 换算为秒


@runtime_checkable
class Runner(Protocol):
    """执行命令的通道（真实 SSH 管理器或自测替身）。"""

    async def run(self, spec: CommandSpec, *, timeout: float | None = None) -> CommandResult: ...

    async def run_raw(self, command: str, *, timeout: float | None = None) -> CommandResult: ...


@dataclass
class ServiceInfo:
    """单个服务的结构化状态。"""

    name: str
    running: bool | None = None
    enabled: bool | None = None
    pid: int | None = None
    started_at: str | None = None
    description: str | None = None
    source: str = "unknown"
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "running": self.running,
            "enabled": self.enabled,
            "pid": self.pid,
            "started_at": self.started_at,
            "description": self.description,
            "source": self.source,
        }
        if self.raw:
            payload["raw"] = self.raw
        return payload


@dataclass
class ActionResult:
    """start / stop / restart 的执行结果。"""

    name: str
    action: ActionName
    exit_status: int
    command: tuple[str, ...]
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    state_before: ServiceInfo | None = None
    state_after: ServiceInfo | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "action": self.action,
            "exit_status": self.exit_status,
            "command": list(self.command),
            "stdout": self.stdout.strip(),
            "stderr": self.stderr.strip(),
            "duration_ms": self.duration_ms,
            "state_before": self.state_before.to_dict() if self.state_before else None,
            "state_after": self.state_after.to_dict() if self.state_after else None,
        }


@dataclass
class LogResult:
    """日志尾部内容。"""

    name: str
    lines: list[str]
    requested_lines: int
    source: str
    command: tuple[str, ...]
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "requested_lines": self.requested_lines,
            "returned_lines": len(self.lines),
            "source": self.source,
            "command": list(self.command),
            "truncated": self.truncated,
            "lines": self.lines,
        }


class ServiceBackend(ABC):
    """具体 init 系统的能力接口。"""

    #: 后端标识，会出现在工具返回值的 source 字段
    name: str = "base"

    def __init__(self, runner: Runner, command_timeout: float = 12.0) -> None:
        self.runner = runner
        self.command_timeout = command_timeout
        self.programs = ProgramResolver(runner)

    # ------------------------------------------------------------------ 基础设施

    async def _run(self, spec: CommandSpec, *, timeout: float | None = None) -> CommandResult:
        if spec.program:
            path = await self.programs.resolve(spec.program)
            spec = spec.with_program_path(path)
        return await self.runner.run(spec, timeout=timeout)

    async def _read_text(self, path: str) -> str | None:
        result = await self._run(read_file(path))
        if result.exit_status != 0:
            return None
        return result.stdout.strip()

    async def read_text(self, path: str) -> str | None:
        """公开版 ``_read_text``，供控制层读取白名单内的文件。"""
        return await self._read_text(path)

    async def uname_text(self) -> str | None:
        """读取 ``uname -a`` 输出。"""
        result = await self._run(uname_cmd())
        if result.exit_status != 0:
            return None
        return result.stdout.strip()

    async def _proc_start_epoch(self, pid: int | None) -> str | None:
        """通过 /proc/<pid>/stat + /proc/stat 的 btime 推算进程启动时间。"""
        if not pid:
            return None
        try:
            stat_result = await self._run(proc_pid_stat(pid))
            uptime_result = await self._run(read_file("/proc/uptime"))
            btime_result = await self._run(read_file("/proc/stat"))
        except ToolError:
            return None
        if stat_result.exit_status != 0:
            return None

        fields = stat_result.stdout[stat_result.stdout.rfind(")") + 1 :].split()
        if len(fields) < 20:
            return None
        try:
            starttime_ticks = int(fields[19])
        except ValueError:
            return None

        btime: int | None = None
        for line in (btime_result.stdout or "").splitlines():
            if line.startswith("btime"):
                try:
                    btime = int(line.split()[1])
                except (IndexError, ValueError):
                    btime = None
                break
        if btime is None:
            return None

        epoch = btime + starttime_ticks / CLK_TCK
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))

    # ------------------------------------------------------------------ 能力

    @abstractmethod
    async def detect(self) -> bool:
        """探测当前主机是否属于该后端。"""

    @abstractmethod
    async def list_services(self, *, with_start_time: bool = False) -> list[ServiceInfo]:
        """列出全部服务。

        ``with_start_time=True`` 时会为每个运行中的服务额外读取 /proc/<pid>/stat
        推算启动时间，命令数随服务数线性增长，默认关闭。
        """

    @abstractmethod
    async def status(self, name: str) -> ServiceInfo:
        """查询单个服务；不存在时抛 SERVICE_NOT_FOUND。"""

    @abstractmethod
    async def action(self, name: str, action: ActionName) -> ActionResult:
        """执行写操作。"""

    @abstractmethod
    async def logs(self, name: str, lines: int) -> LogResult:
        """读取服务日志尾部。"""


def backend_error(message: str, *, hint: str = "", details: dict[str, Any] | None = None) -> ToolError:
    return ToolError(ErrorCode.BACKEND_ERROR, message, hint=hint, details=details or {})
