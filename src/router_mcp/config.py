"""配置加载：默认值 < JSON 配置文件 < 环境变量。

优先级（后者覆盖前者）：
    1. 代码内默认值
    2. 配置文件（--config 指定 / $ROUTER_MCP_CONFIG / ./router-mcp.json / ~/.config/router-mcp/config.json）
    3. 环境变量（ROUTER_MCP_*）

密钥相关字段不会被打印到日志或工具返回值中（见 :func:`SSHConfig.redacted`）。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ErrorCode, ToolError

ENV_PREFIX = "ROUTER_MCP_"

DEFAULT_CONFIG_LOCATIONS: tuple[str, ...] = (
    "router-mcp.json",
    "config.json",
    str(Path.home() / ".config" / "router-mcp" / "config.json"),
)


def _env(name: str) -> str | None:
    value = os.environ.get(ENV_PREFIX + name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ToolError(
            ErrorCode.CONFIG_ERROR,
            f"环境变量 {ENV_PREFIX}{name} 不是合法整数：{raw!r}",
            hint="请填写秒数（整数），例如 ROUTER_MCP_COMMAND_TIMEOUT=15",
        ) from exc


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ToolError(
            ErrorCode.CONFIG_ERROR,
            f"环境变量 {ENV_PREFIX}{name} 不是合法数值：{raw!r}",
            hint="请填写数值（秒），例如 ROUTER_MCP_CONNECT_TIMEOUT=8.0",
        ) from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _env_list(name: str) -> tuple[str, ...]:
    raw = _env(name)
    if not raw:
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Limits:
    """运行期阈值，全部可通过环境变量覆盖。"""

    connect_timeout: float = 8.0
    command_timeout: float = 12.0
    keepalive_interval: int = 15
    keepalive_count: int = 3
    max_reconnect_attempts: int = 2
    reconnect_backoff: float = 1.0
    max_log_lines: int = 500


@dataclass(frozen=True)
class SecurityPolicy:
    """安全策略：写入确认、服务白名单、主机密钥校验、shell 能力开关。"""

    require_confirmation: bool = True
    allowed_services: tuple[str, ...] = field(default_factory=tuple)  # 为空表示不限制
    denied_services: tuple[str, ...] = ("network", "firewall", "system", "boot", "done")
    strict_host_key: bool = False
    known_hosts_path: str | None = None
    # shell 能力（高危，默认全部关闭）
    allow_shell: bool = False
    shell_require_confirm: bool = True
    shell_deny_unsafe: bool = True


@dataclass(frozen=True)
class SSHConfig:
    """SSH 连接参数。"""

    host: str = "192.168.1.1"
    port: int = 22
    username: str = "root"
    password: str | None = None
    key_path: str | None = None
    key_passphrase: str | None = None
    init_system: str = "auto"  # auto | procd | systemd | sysvinit
    limits: Limits = field(default_factory=Limits)
    security: SecurityPolicy = field(default_factory=SecurityPolicy)

    def __post_init__(self) -> None:
        if not self.host:
            raise ToolError(ErrorCode.CONFIG_ERROR, "缺少 SSH 主机地址（host）")
        if not 1 <= self.port <= 65535:
            raise ToolError(ErrorCode.CONFIG_ERROR, f"SSH 端口非法：{self.port}")
        if not self.username:
            raise ToolError(ErrorCode.CONFIG_ERROR, "缺少 SSH 用户名（username）")
        if not self.password and not self.key_path:
            raise ToolError(
                ErrorCode.CONFIG_ERROR,
                "未提供任何认证方式",
                hint=(
                    "请设置 ROUTER_MCP_PASSWORD 或 ROUTER_MCP_KEY_PATH（私钥路径），"
                    "也可在配置文件中填写 password / key_path"
                ),
            )
        if self.key_path and not Path(self.key_path).expanduser().exists():
            raise ToolError(
                ErrorCode.CONFIG_ERROR,
                f"私钥文件不存在：{self.key_path}",
                hint="检查 ROUTER_MCP_KEY_PATH 是否指向可读取的 OpenSSH/ PEM 私钥",
            )
        if self.init_system not in {"auto", "procd", "systemd", "sysvinit"}:
            raise ToolError(
                ErrorCode.CONFIG_ERROR,
                f"未知的 init 系统：{self.init_system}",
                hint="可选值：auto / procd / systemd / sysvinit",
            )

    @property
    def target(self) -> str:
        return f"{self.username}@{self.host}:{self.port}"

    def redacted(self) -> dict[str, Any]:
        """返回可安全展示的配置快照（不含口令）。"""
        return {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "auth_method": "key" if self.key_path else "password",
            "key_path": self.key_path,
            "init_system": self.init_system,
            "limits": {
                "connect_timeout": self.limits.connect_timeout,
                "command_timeout": self.limits.command_timeout,
                "keepalive_interval": self.limits.keepalive_interval,
                "keepalive_count": self.limits.keepalive_count,
                "max_reconnect_attempts": self.limits.max_reconnect_attempts,
                "max_log_lines": self.limits.max_log_lines,
            },
            "security": {
                "require_confirmation": self.security.require_confirmation,
                "allowed_services": list(self.security.allowed_services),
                "denied_services": list(self.security.denied_services),
                "strict_host_key": self.security.strict_host_key,
                "known_hosts_path": self.security.known_hosts_path,
                "allow_shell": self.security.allow_shell,
                "shell_require_confirm": self.security.shell_require_confirm,
                "shell_deny_unsafe": self.security.shell_deny_unsafe,
            },
        }


def load_config_file(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """读取 JSON 配置文件；未找到时返回空字典。"""
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path).expanduser())
    elif env_path := _env("CONFIG"):
        candidates.append(Path(env_path).expanduser())
    else:
        candidates.extend(Path(p).expanduser() for p in DEFAULT_CONFIG_LOCATIONS)

    for candidate in candidates:
        if candidate.is_file():
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ToolError(
                    ErrorCode.CONFIG_ERROR,
                    f"配置文件 {candidate} 不是合法 JSON：{exc}",
                    hint="检查语法（不支持注释与尾随逗号）",
                ) from exc
            if not isinstance(data, dict):
                raise ToolError(
                    ErrorCode.CONFIG_ERROR,
                    f"配置文件 {candidate} 顶层必须是对象",
                )
            data["__source__"] = str(candidate)
            return data
    if path:
        raise ToolError(
            ErrorCode.CONFIG_ERROR,
            f"指定的配置文件不存在：{path}",
            hint="确认路径，或改用环境变量 ROUTER_MCP_CONFIG",
        )
    return {}


def load_config(path: str | os.PathLike[str] | None = None) -> SSHConfig:
    """按优先级合并配置并最终校验。"""
    file_data = {k: v for k, v in load_config_file(path).items() if k != "__source__"}
    limits_data: dict[str, Any] = dict(file_data.get("limits") or {})
    security_data: dict[str, Any] = dict(file_data.get("security") or {})

    limits = Limits(
        connect_timeout=_env_float("CONNECT_TIMEOUT", float(limits_data.get("connect_timeout", 8.0))),
        command_timeout=_env_float("COMMAND_TIMEOUT", float(limits_data.get("command_timeout", 12.0))),
        keepalive_interval=_env_int(
            "KEEPALIVE_INTERVAL", int(limits_data.get("keepalive_interval", 15))
        ),
        keepalive_count=_env_int("KEEPALIVE_COUNT", int(limits_data.get("keepalive_count", 3))),
        max_reconnect_attempts=_env_int(
            "MAX_RECONNECT_ATTEMPTS", int(limits_data.get("max_reconnect_attempts", 2))
        ),
        reconnect_backoff=_env_float(
            "RECONNECT_BACKOFF", float(limits_data.get("reconnect_backoff", 1.0))
        ),
        max_log_lines=_env_int("MAX_LOG_LINES", int(limits_data.get("max_log_lines", 500))),
    )

    security = SecurityPolicy(
        require_confirmation=_env_bool(
            "REQUIRE_CONFIRM", bool(security_data.get("require_confirmation", True))
        ),
        allowed_services=_env_list("ALLOWED_SERVICES")
        or tuple(security_data.get("allowed_services") or ()),
        denied_services=_env_list("DENIED_SERVICES")
        or tuple(security_data.get("denied_services") or SecurityPolicy().denied_services),
        strict_host_key=_env_bool("STRICT_HOST_KEY", bool(security_data.get("strict_host_key", False))),
        known_hosts_path=_env("KNOWN_HOSTS") or security_data.get("known_hosts_path"),
        allow_shell=_env_bool("ALLOW_SHELL", bool(security_data.get("allow_shell", False))),
        shell_require_confirm=_env_bool(
            "SHELL_REQUIRE_CONFIRM", bool(security_data.get("shell_require_confirm", True))
        ),
        shell_deny_unsafe=_env_bool(
            "SHELL_DENY_UNSAFE", bool(security_data.get("shell_deny_unsafe", True))
        ),
    )

    return SSHConfig(
        host=_env("HOST") or str(file_data.get("host") or "192.168.1.1"),
        port=_env_int("PORT", int(file_data.get("port") or 22)),
        username=_env("USER") or str(file_data.get("username") or "root"),
        password=_env("PASSWORD") or file_data.get("password"),
        key_path=_env("KEY_PATH") or file_data.get("key_path"),
        key_passphrase=_env("KEY_PASSPHRASE") or file_data.get("key_passphrase"),
        init_system=_env("INIT_SYSTEM") or str(file_data.get("init_system") or "auto"),
        limits=limits,
        security=security,
    )
