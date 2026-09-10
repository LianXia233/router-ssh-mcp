"""SSH 连接管理：连接复用、保活、超时重连与错误归类。

设计要点
    * 单连接复用：同一进程内对同一路由器复用一条 SSH 连接，避免频繁握手。
    * 保活：``set_keepalive(interval, count_max)`` 主动探测，静默断链会被快速发现。
    * 超时重连：命令执行超时或连接断开时丢弃旧连接，按退避策略重连并重试一次。
    * 错误归类：把 asyncssh 的异常映射到稳定的 :class:`ErrorCode`。
"""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
import time
from dataclasses import dataclass, field
from typing import Any, Sequence

import asyncssh

from .commands import CommandSpec
from .config import SSHConfig
from .errors import ErrorCode, ToolError

# asyncssh 默认会向 stderr 输出 DEBUG 级握手日志，既嘈杂又可能泄露连接细节。
# stdio 传输只使用 stdout，协议本身不受影响，但默认仍收敛到 WARNING。
logging.getLogger("asyncssh").setLevel(
    os.environ.get("ROUTER_MCP_LOG_LEVEL", "WARNING").upper()
)


def render_command(argv: Sequence[str]) -> str:
    """把 argv 渲染成下发到远端的命令行字符串。

    SSH 的 exec 通道只接受**整条命令字符串**，远端（busybox/dropbear）会用
    login shell 再解析一次；asyncssh 2.24 的 ``run()`` 也不接受 list 参数。
    因此这里对每个参数做 POSIX shell 转义（shlex.join）后再拼接：

        * 每个参数在远端被还原为**一个** argv 项（含空格的 JSON 参数也能正确传递）
        * 引号、``$``、反引号、分号等元字符一律被单引号包裹转义，无法逃逸出参数边界
        * 上层 commands.py 的白名单校验仍然生效，这里是第二道防线
    """
    return shlex.join(argv)


@dataclass(frozen=True)
class CommandResult:
    """一次远程命令执行结果。"""

    argv: tuple[str, ...]
    exit_status: int
    stdout: str
    stderr: str
    duration_ms: int
    host: str
    reused_connection: bool = True

    @property
    def ok(self) -> bool:
        return self.exit_status == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "exit_status": self.exit_status,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "host": self.host,
            "reused_connection": self.reused_connection,
        }


@dataclass
class _ConnState:
    conn: asyncssh.SSHClientConnection | None = None
    established_at: float = 0.0
    reuse_count: int = 0
    last_error: str | None = None
    reconnect_count: int = 0


class SSHConnectionManager:
    """维护到目标路由器的单条 SSH 连接。"""

    def __init__(self, config: SSHConfig) -> None:
        self._config = config
        self._state = _ConnState()
        self._lock = asyncio.Lock()
        self._peer_banner: str | None = None

    # ------------------------------------------------------------------ 连接

    def _connect_kwargs(self) -> dict[str, Any]:
        cfg = self._config
        kwargs: dict[str, Any] = {
            "host": cfg.host,
            "port": cfg.port,
            "username": cfg.username,
            "connect_timeout": cfg.limits.connect_timeout,
            "login_timeout": cfg.limits.connect_timeout * 2,
        }
        if cfg.key_path:
            kwargs["client_keys"] = [cfg.key_path]
            # 私钥口令：优先专用变量；若用户只填了 password，也尝试作为私钥口令，
            # 这样「密钥 + 口令」与「密钥 + 登录密码」两种习惯都能工作。
            kwargs["passphrase"] = cfg.key_passphrase or cfg.password
        if cfg.password:
            kwargs["password"] = cfg.password

        if cfg.security.strict_host_key:
            known = cfg.security.known_hosts_path or None
            kwargs["known_hosts"] = known  # None -> 使用默认 ~/.ssh/known_hosts
        else:
            kwargs["known_hosts"] = None  # 路由器常见自签/重装场景，默认不校验
        return kwargs

    async def _open(self) -> asyncssh.SSHClientConnection:
        cfg = self._config
        try:
            conn = await asyncssh.connect(**self._connect_kwargs())
        except asyncio.TimeoutError as exc:
            raise ToolError(
                ErrorCode.CONNECTION_FAILED,
                f"连接 {cfg.target} 超时（>{cfg.limits.connect_timeout}s）",
                hint="确认主机在线、端口可达，以及本机到路由器的路由/防火墙策略",
                details={"host": cfg.host, "port": cfg.port, "timeout": cfg.limits.connect_timeout},
            ) from exc
        except asyncssh.PermissionDenied as exc:
            raise ToolError(
                ErrorCode.AUTH_FAILED,
                f"SSH 认证失败：{cfg.username}@{cfg.host}",
                hint="检查用户名/密码或私钥是否正确；OpenWrt 默认用户为 root，且需确认 dropbear 允许密码登录",
                details={"host": cfg.host, "username": cfg.username, "reason": str(exc)},
            ) from exc
        except asyncssh.HostKeyNotVerifiable as exc:  # type: ignore[attr-defined]
            raise ToolError(
                ErrorCode.HOST_KEY_UNVERIFIED,
                f"主机密钥校验失败：{cfg.host}",
                hint="若路由器重装过系统，请更新 known_hosts；或设置 ROUTER_MCP_STRICT_HOST_KEY=false",
                details={"host": cfg.host, "reason": str(exc)},
            ) from exc
        except (OSError, asyncssh.Error) as exc:
            raise ToolError(
                ErrorCode.CONNECTION_FAILED,
                f"无法建立到 {cfg.target} 的 SSH 连接：{exc}",
                hint="检查 host/port、网络连通性与 SSH 服务（dropbear/sshd）是否运行",
                details={"host": cfg.host, "port": cfg.port, "error_type": type(exc).__name__},
            ) from exc

        try:
            conn.set_keepalive(
                cfg.limits.keepalive_interval, cfg.limits.keepalive_count
            )
        except Exception:  # pragma: no cover - 个别实现不支持保活
            pass
        self._peer_banner = str(conn.get_extra_info("server_version") or "")
        return conn

    def _is_alive(self, conn: asyncssh.SSHClientConnection | None) -> bool:
        if conn is None:
            return False
        if conn.is_closed():
            return False
        return True

    async def _drop(self) -> None:
        conn, self._state.conn = self._state.conn, None
        if conn is not None and not conn.is_closed():
            try:
                conn.close()
            except Exception:  # pragma: no cover
                pass
            try:
                await conn.wait_closed()
            except Exception:  # pragma: no cover
                pass

    async def get_connection(self, *, force_new: bool = False) -> asyncssh.SSHClientConnection:
        """返回可用连接；必要时重连。"""
        async with self._lock:
            if force_new:
                await self._drop()
            if not self._is_alive(self._state.conn):
                await self._drop()
                conn = await self._open()
                self._state.conn = conn
                self._state.established_at = time.monotonic()
                self._state.reconnect_count += 1
            assert self._state.conn is not None
            return self._state.conn

    # ------------------------------------------------------------------ 执行

    async def _execute(self, command_str: str, *, timeout: float | None = None) -> CommandResult:
        """执行一条命令字符串（已渲染），带连接复用、超时与重连。

        ``run``（白名单 argv）与 ``run_raw``（任意 shell）共用本方法，仅命令字符串来源不同。
        """
        cfg = self._config
        timeout = timeout if timeout is not None else cfg.limits.command_timeout
        attempts = max(1, cfg.limits.max_reconnect_attempts)
        last_error: ToolError | None = None
        preview = command_str if len(command_str) <= 200 else command_str[:200] + "..."

        for attempt in range(1, attempts + 1):
            try:
                conn = await self.get_connection(force_new=attempt > 1)
            except ToolError:
                raise

            reused = self._state.reuse_count > 0
            started = time.perf_counter()
            try:
                completed = await asyncio.wait_for(
                    conn.run(command_str, check=False), timeout=timeout
                )
            except asyncio.TimeoutError as exc:
                last_error = ToolError(
                    ErrorCode.COMMAND_TIMEOUT,
                    f"命令 {preview!r} 执行超时（>{timeout}s）",
                    hint="提高 ROUTER_MCP_COMMAND_TIMEOUT，或确认设备负载/网络是否异常",
                    details={"timeout": timeout, "attempt": attempt},
                )
                await self._drop()
                continue
            except (asyncssh.ConnectionLost, asyncssh.ChannelOpenError, BrokenPipeError) as exc:
                self._state.last_error = str(exc)
                last_error = ToolError(
                    ErrorCode.CONNECTION_FAILED,
                    f"SSH 连接在执行过程中断开：{type(exc).__name__}",
                    hint="将自动重连重试；若频繁出现请检查设备 SSH 服务的 MaxSessions 与网络稳定性",
                    details={"attempt": attempt, "reason": str(exc)},
                )
                await self._drop()
                continue
            except asyncssh.PermissionDenied as exc:  # 通道级鉴权失败
                raise ToolError(
                    ErrorCode.AUTH_FAILED,
                    f"执行命令时鉴权失败：{exc}",
                    hint="确认该用户具备执行命令的权限（OpenWrt root 无 sudo 概念）",
                ) from exc
            except asyncssh.Error as exc:
                raise ToolError(
                    ErrorCode.CONNECTION_FAILED,
                    f"SSH 协议错误：{type(exc).__name__}: {exc}",
                    hint="检查 SSH 服务端版本兼容性",
                    details={},
                ) from exc

            self._state.reuse_count += 1
            duration_ms = int((time.perf_counter() - started) * 1000)
            return CommandResult(
                argv=tuple(shlex.split(command_str)),
                exit_status=int(completed.exit_status if completed.exit_status is not None else -1),
                stdout=completed.stdout or "",
                stderr=completed.stderr or "",
                duration_ms=duration_ms,
                host=cfg.host,
                reused_connection=reused,
            )

        assert last_error is not None
        raise last_error

    async def run(self, spec: CommandSpec, *, timeout: float | None = None) -> CommandResult:
        """执行白名单命令（argv 经 POSIX 转义后下发），返回结构化结果。"""
        return await self._execute(render_command(spec.argv), timeout=timeout)

    async def run_raw(self, command: str, *, timeout: float | None = None) -> CommandResult:
        """执行任意 shell 命令字符串（高危，仅当 security.allow_shell=true 时由上层调用）。

        命令字符串会原样交给远端登录 shell 解析——这正是 shell 能力的语义。
        连接复用、超时与重连逻辑与 ``run`` 完全一致。
        """
        return await self._execute(command, timeout=timeout)

    # ------------------------------------------------------------------ 运维

    async def health(self) -> dict[str, Any]:
        """连接健康快照，用于自测与排障。"""
        server_version = self._peer_banner
        if self._is_alive(self._state.conn) and self._state.conn is not None:
            server_version = (
                self._state.conn.get_extra_info("server_version") or self._peer_banner
            )
        info: dict[str, Any] = {
            "host": self._config.host,
            "port": self._config.port,
            "username": self._config.username,
            "connected": self._is_alive(self._state.conn),
            "reuse_count": self._state.reuse_count,
            "reconnect_count": self._state.reconnect_count,
            "uptime_seconds": (
                round(time.monotonic() - self._state.established_at, 1)
                if self._state.established_at
                else 0.0
            ),
            "server_version": server_version,
            "last_error": self._state.last_error,
        }
        return info

    async def close(self) -> None:
        async with self._lock:
            await self._drop()

    async def __aenter__(self) -> "SSHConnectionManager":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()


def decode_output(raw: str | bytes | None) -> str:
    """统一把远端输出转为字符串。"""
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return raw


@dataclass
class FakeScript:
    """自测替身：按 argv 匹配返回预设输出，用于离线端到端测试。"""

    pattern: tuple[str, ...]
    stdout: str = ""
    stderr: str = ""
    exit_status: int = 0
    delay: float = 0.0

    def matches(self, argv: Sequence[str]) -> bool:
        if len(argv) < len(self.pattern):
            return False
        return tuple(argv[: len(self.pattern)]) == self.pattern


@dataclass
class FakeConnectionManager:
    """离线替身管理器，接口与 :class:`SSHConnectionManager` 兼容。"""

    scripts: list[FakeScript] = field(default_factory=list)
    # 任意 shell 命令的匹配脚本：命中子串即按预设返回（用于 shell 能力测试）
    raw_scripts: list[tuple[str, str, str, int]] = field(default_factory=list)
    calls: list[tuple[str, ...]] = field(default_factory=list)
    raw_calls: list[str] = field(default_factory=list)
    health_info: dict[str, Any] = field(default_factory=dict)

    async def run(self, spec: CommandSpec, *, timeout: float | None = None) -> CommandResult:
        import asyncio as _asyncio

        self.calls.append(spec.argv)
        for script in self.scripts:
            if script.matches(spec.argv):
                if script.delay and timeout is not None and script.delay > timeout:
                    await _asyncio.sleep(timeout)
                    raise ToolError(
                        ErrorCode.COMMAND_TIMEOUT,
                        f"命令 {spec.display!r} 执行超时（>{timeout}s）",
                        hint="自测替身模拟超时",
                        details={"argv": list(spec.argv), "timeout": timeout},
                    )
                if script.delay:
                    await _asyncio.sleep(script.delay)
                return CommandResult(
                    argv=spec.argv,
                    exit_status=script.exit_status,
                    stdout=script.stdout,
                    stderr=script.stderr,
                    duration_ms=int(script.delay * 1000),
                    host="fake-host",
                    reused_connection=True,
                )
        return CommandResult(
            argv=spec.argv,
            exit_status=127,
            stdout="",
            stderr=f"command not found: {' '.join(spec.argv)}",
            duration_ms=1,
            host="fake-host",
        )

    async def run_raw(self, command: str, *, timeout: float | None = None) -> CommandResult:
        self.raw_calls.append(command)
        for substring, stdout, stderr, exit_status in self.raw_scripts:
            if substring in command:
                return CommandResult(
                    argv=tuple(command.split()),
                    exit_status=exit_status,
                    stdout=stdout,
                    stderr=stderr,
                    duration_ms=1,
                    host="fake-host",
                    reused_connection=True,
                )
        return CommandResult(
            argv=tuple(command.split()),
            exit_status=0,
            stdout="",
            stderr="",
            duration_ms=1,
            host="fake-host",
            reused_connection=True,
        )

    async def health(self) -> dict[str, Any]:
        base = {
            "host": "fake-host",
            "connected": True,
            "reuse_count": len(self.calls),
            "reconnect_count": 0,
            "uptime_seconds": 0.0,
            "server_version": "fake-ssh-1.0",
            "last_error": None,
        }
        base.update(self.health_info)
        return base

    async def close(self) -> None:
        return None
