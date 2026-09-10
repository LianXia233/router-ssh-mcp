"""业务控制器：连接、后端、安全策略与工具语义的编排层。"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any

from .backends import resolve_backend
from .backends.base import ActionName, Runner, ServiceBackend
from .commands import validate_lines, validate_service_name, validate_shell_command
from .config import SSHConfig
from .errors import ErrorCode, ToolError
from .ssh_pool import SSHConnectionManager

WRITE_ACTIONS: tuple[ActionName, ...] = ("start", "stop", "restart", "reload")

#: 连接器能力标识：供上层软件识别「这是一个可通过 SSH 管理路由器的 MCP 连接器」。
CONNECTOR_CAPABILITY = "ssh-router-management"


class RouterController:
    """对外暴露的高层能力，MCP 工具层只调用这里。"""

    def __init__(self, config: SSHConfig, runner: Runner | None = None) -> None:
        self.config = config
        self.runner: Runner = runner or SSHConnectionManager(config)
        self._backend: ServiceBackend | None = None
        self._backend_at: float = 0.0

    # ------------------------------------------------------------------ 后端

    async def backend(self, *, refresh: bool = False) -> ServiceBackend:
        if self._backend is None or refresh:
            self._backend = await resolve_backend(self.runner, self.config)
            self._backend_at = time.monotonic()
        return self._backend

    async def init_system(self) -> str:
        return (await self.backend()).name

    # ------------------------------------------------------------------ 安全

    def guard(self, name: str, *, write: bool) -> str:
        """服务名校验 + 白/黑名单策略，返回规范化名称。"""
        service = validate_service_name(name)
        policy = self.config.security
        denied = {item.lower() for item in policy.denied_services}
        allowed = {item.lower() for item in policy.allowed_services}

        if allowed and service.lower() not in allowed:
            raise ToolError(
                ErrorCode.PERMISSION_DENIED,
                f"服务 {service!r} 不在允许操作的服务白名单内",
                hint="通过 ROUTER_MCP_ALLOWED_SERVICES 或配置文件 security.allowed_services 放开",
                details={"allowed_services": list(policy.allowed_services)},
            )
        if write and service.lower() in denied:
            raise ToolError(
                ErrorCode.PERMISSION_DENIED,
                f"服务 {service!r} 属于高风险服务，已拒绝写入操作",
                hint="重启 network/firewall 等操作会中断联网，请登录设备手动执行；"
                "确需放开时调整 security.denied_services",
                details={"denied_services": list(policy.denied_services)},
            )
        return service

    def require_confirmation(self, service: str, action: ActionName, confirm: str | None) -> None:
        """写入操作的二次确认：confirm 必须与服务名完全一致。"""
        if not self.config.security.require_confirmation:
            return
        if confirm != service:
            raise ToolError(
                ErrorCode.CONFIRMATION_REQUIRED,
                f"写入操作 {action} 需要二次确认",
                hint=f"确认无误后再次调用，并传入 confirm=\"{service}\"；"
                "也可设置 ROUTER_MCP_REQUIRE_CONFIRM=false 关闭（不推荐）",
                details={
                    "service": service,
                    "action": action,
                    "expected_confirm": service,
                    "received_confirm": confirm,
                },
            )

    # ------------------------------------------------------------------ 能力

    async def list_services(
        self,
        *,
        name_filter: str | None = None,
        running_only: bool = False,
        with_start_time: bool = False,
    ) -> tuple[list[Any], str, list[str]]:
        backend = await self.backend()
        services = await backend.list_services(with_start_time=with_start_time)
        warnings: list[str] = []

        if name_filter:
            keyword = name_filter.lower()
            services = [svc for svc in services if keyword in svc.name.lower()]
        if running_only:
            services = [svc for svc in services if svc.running is True]
        if not with_start_time:
            warnings.append("started_at 仅在 service_status 或 with_start_time=true 时返回")
        return [svc.to_dict() for svc in services], backend.name, warnings

    async def status(self, name: str) -> dict[str, Any]:
        service = self.guard(name, write=False)
        backend = await self.backend()
        info = await backend.status(service)
        return {
            "service": info.to_dict(),
            "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "init_system": backend.name,
        }

    async def perform_action(self, name: str, action: ActionName, confirm: str | None) -> dict[str, Any]:
        service = self.guard(name, write=True)
        self.require_confirmation(service, action, confirm)
        backend = await self.backend()
        result = await backend.action(service, action)
        return result.to_dict()

    async def logs(self, name: str, lines: int) -> dict[str, Any]:
        service = self.guard(name, write=False)
        lines = validate_lines(lines, self.config.limits.max_log_lines)
        backend = await self.backend()
        result = await backend.logs(service, lines)
        return result.to_dict()

    # ------------------------------------------------------------------ shell

    async def run_shell(self, command: str, confirm: str | None) -> dict[str, Any]:
        """在路由器上执行任意 shell 命令（高危能力）。

        安全门禁（任意一条不满足都直接返回结构化错误）：
            * security.allow_shell 必须为 true，否则 SHELL_DISABLED；
            * 命令经 :func:`validate_shell_command` 校验，默认命中高危拦截列表会被 BLOCKED_COMMAND；
            * 若 security.shell_require_confirm 为 true（默认），confirm 必须等于命令本身，
              否则 CONFIRMATION_REQUIRED。

        命令以 root 身份在远端登录 shell 中执行，绕过服务白名单，结果进入审计日志。
        """
        policy = self.config.security
        if not policy.allow_shell:
            raise ToolError(
                ErrorCode.SHELL_DISABLED,
                "shell 能力未启用",
                hint=(
                    "设置 ROUTER_MCP_ALLOW_SHELL=true 开启本能力；"
                    "默认关闭是为了避免任意命令执行风险"
                ),
                details={"allow_shell": policy.allow_shell},
            )

        validated = validate_shell_command(command, deny_unsafe=policy.shell_deny_unsafe)

        if policy.shell_require_confirm:
            if confirm != validated:
                raise ToolError(
                    ErrorCode.CONFIRMATION_REQUIRED,
                    "shell 命令需要二次确认",
                    hint=(
                        f'请再次调用并传入 confirm="{validated}"'
                        f'（需与命令本身完全一致，包括空格与引号）'
                    ),
                    details={
                        "expected_confirm": validated,
                        "received_confirm": confirm,
                    },
                )

        logging.info(
            "router-ssh-mcp shell exec (host=%s, user=%s): %s",
            self.config.host,
            self.config.username,
            validated,
        )

        result = await self.runner.run_raw(
            validated, timeout=self.config.limits.command_timeout
        )
        return {
            "raw_command": validated,
            "exit_status": result.exit_status,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration_ms": result.duration_ms,
            "host": result.host,
            "reused_connection": result.reused_connection,
            "denied": False,
            "confirmed": bool(policy.shell_require_confirm),
            "warning": (
                "命令以 root 身份在路由器上执行，已绕过服务白名单；请确认输出不含敏感信息"
                if result.exit_status == 0
                else None
            ),
        }

    # ------------------------------------------------------------------ 运维

    async def info(self) -> dict[str, Any]:
        # 先解析后端（会建立连接），再取连接健康，避免 health 早于握手
        backend = await self.backend()
        health = await self.runner.health()
        device: dict[str, Any] = {}
        try:
            # 统一走后端执行，确保程序路径占位符被解析
            uname_text = await backend.uname_text()
            if uname_text:
                device["uname"] = uname_text
            for path in ("/etc/openwrt_release", "/etc/os-release"):
                release = await backend.read_text(path)
                if release:
                    device["release"] = release
                    device["release_source"] = path
                    break
        except ToolError as exc:
            device["error"] = exc.to_payload()
        device["program_paths"] = backend.programs.snapshot()

        warnings: list[str] = []
        if not health.get("connected"):
            warnings.append("SSH 当前未建立连接（首次工具调用会按需连接）")
        if health.get("last_error"):
            warnings.append(f"最近一次连接错误：{health['last_error']}")
        if "error" in device:
            warnings.append("设备信息读取失败，详见 data.device.error")

        return {
            "host": self.config.host,
            "port": self.config.port,
            "username": self.config.username,
            "backend": backend.name,
            "capability": CONNECTOR_CAPABILITY,
            "ssh": health,
            "device": device,
            "security": self.config.security.__dict__ | {},
            "limits": self.config.limits.__dict__ | {},
            "warnings": warnings,
        }

    async def close(self) -> None:
        close = getattr(self.runner, "close", None)
        if close is not None:
            await close()
