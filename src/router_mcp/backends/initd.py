"""SysV init / OpenWrt init.d 脚本后端。

OpenWrt 的 procd 与传统的 sysvinit 都通过 ``/etc/init.d/<name> start|stop|restart|status``
管理，差别只在于状态查询渠道（procd 走 ubus，sysvinit 只能靠脚本退出码 + pidof）。
这里实现通用部分，procd 后端继承后覆盖状态查询。
"""

from __future__ import annotations

import json
from typing import Any

from ..commands import (
    init_d_action,
    list_dir,
    logread_tail,
    pidof,
    tail_file,
)
from ..errors import ErrorCode, ToolError
from ..ssh_pool import CommandResult
from .base import ActionName, ActionResult, LogResult, ServiceBackend, ServiceInfo

#: /etc/init.d 下需忽略的非服务条目
INIT_D_IGNORE = {
    "README",
    "functions",
    "rc.common",
    "rcS",
    "S01sysfixtime",
    "Makefile",
}


class InitScriptBackend(ServiceBackend):
    name = "sysvinit"

    # ------------------------------------------------------------------ 探测

    async def detect(self) -> bool:
        """sysvinit 作为兜底后端：只要 /etc/init.d 可读即认为可用。"""
        result = await self._run(list_dir("/etc/init.d"))
        return result.exit_status == 0

    # ------------------------------------------------------------------ 目录工具

    async def init_scripts(self) -> list[str]:
        result = await self._run(list_dir("/etc/init.d"))
        if result.exit_status != 0:
            return []
        names = []
        for line in result.stdout.splitlines():
            name = line.strip()
            if not name or name in INIT_D_IGNORE or name.startswith("."):
                continue
            names.append(name)
        return sorted(set(names))

    async def enabled_map(self) -> dict[str, bool]:
        """解析 /etc/rc.d 中的 S*/K* 链接判断开机自启。"""
        result = await self._run(list_dir("/etc/rc.d"))
        mapping: dict[str, bool] = {}
        if result.exit_status != 0:
            return mapping
        for line in result.stdout.splitlines():
            entry = line.strip()
            if len(entry) < 4 or entry[0] not in {"S", "K"}:
                continue
            service = entry[3:]
            if not service:
                continue
            # 同一服务可能同时存在 S 与 K 链接，S（开机启动）优先
            if entry[0] == "S":
                mapping[service] = True
            elif service not in mapping:
                mapping[service] = False
        return mapping

    async def require_script(self, name: str) -> None:
        scripts = await self.init_scripts()
        if name not in scripts:
            raise ToolError(
                ErrorCode.SERVICE_NOT_FOUND,
                f"服务 {name!r} 不存在（未在 /etc/init.d 中找到对应脚本）",
                hint="调用 service_list 获取可用服务名；注意区分大小写",
                details={"available_sample": scripts[:20], "available_count": len(scripts)},
            )

    # ------------------------------------------------------------------ 状态

    async def list_services(self, *, with_start_time: bool = False) -> list[ServiceInfo]:
        scripts = await self.init_scripts()
        enabled = await self.enabled_map()
        services: list[ServiceInfo] = []
        for name in scripts:
            services.append(
                ServiceInfo(
                    name=name,
                    running=None,  # sysvinit 无统一查询通道，避免对全部脚本逐个 status
                    enabled=enabled.get(name),
                    source=self.name,
                    description="init.d 脚本（未查询运行状态，使用 service_status 获取详情）",
                )
            )
        return services

    async def status(self, name: str) -> ServiceInfo:
        await self.require_script(name)
        result = await self._run(init_d_action(name, "status"))
        # init.d status 约定：0 = 运行；3 = 已停止；4 = 状态未知（LSB）
        running: bool | None
        if result.exit_status == 0:
            running = True
        elif result.exit_status in (3, 1):
            running = False
        else:
            running = None

        pid: int | None = None
        if running:
            pid_result = await self._run(pidof(name))
            if pid_result.exit_status == 0 and pid_result.stdout.strip():
                try:
                    pid = int(pid_result.stdout.split()[0])
                except ValueError:
                    pid = None

        started_at = await self._proc_start_epoch(pid) if pid else None
        enabled = (await self.enabled_map()).get(name)
        return ServiceInfo(
            name=name,
            running=running,
            enabled=enabled,
            pid=pid,
            started_at=started_at,
            source=self.name,
            description=(result.stdout or result.stderr).strip() or None,
            raw={"status_exit_code": result.exit_status},
        )

    # ------------------------------------------------------------------ 动作

    async def action(self, name: str, action: ActionName) -> ActionResult:
        await self.require_script(name)
        try:
            before = await self.status(name)
        except ToolError:
            before = None

        result = await self._run(init_d_action(name, action), timeout=self.command_timeout * 2)
        if result.exit_status != 0:
            raise ToolError(
                ErrorCode.COMMAND_FAILED,
                f"执行 {action} 失败（退出码 {result.exit_status}）",
                hint="查看 stderr：常见原因是脚本依赖缺失或已在目标状态",
                details={
                    "service": name,
                    "action": action,
                    "exit_status": result.exit_status,
                    "stderr": result.stderr.strip()[:500],
                    "stdout": result.stdout.strip()[:500],
                },
            )

        after = await self.status(name)
        return ActionResult(
            name=name,
            action=action,
            exit_status=result.exit_status,
            command=result.argv,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_ms=result.duration_ms,
            state_before=before,
            state_after=after,
        )

    # ------------------------------------------------------------------ 日志

    async def logs(self, name: str, lines: int) -> LogResult:
        await self.require_script(name)
        filtered = await self._run(logread_tail(lines, name))
        if filtered.exit_status == 0 and filtered.stdout.strip():
            return LogResult(
                name=name,
                lines=filtered.stdout.splitlines()[-lines:],
                requested_lines=lines,
                source="logread",
                command=filtered.argv,
            )

        # 回退：读全量日志后在本地按关键字过滤（避免把 pattern 拼进 shell）
        full = await self._run(logread_tail(lines * 5))
        if full.exit_status == 0:
            matched = [line for line in full.stdout.splitlines() if name in line]
            return LogResult(
                name=name,
                lines=matched[-lines:],
                requested_lines=lines,
                source="logread(filtered)",
                command=full.argv,
                truncated=len(matched) > lines,
            )

        log_file = await self._run(tail_file(f"/var/log/{name}.log", lines))
        if log_file.exit_status == 0:
            return LogResult(
                name=name,
                lines=log_file.stdout.splitlines()[-lines:],
                requested_lines=lines,
                source=f"/var/log/{name}.log",
                command=log_file.argv,
            )

        raise ToolError(
            ErrorCode.UNSUPPORTED_ACTION,
            f"无法读取 {name} 的日志：logread 不可用且 /var/log/{name}.log 不存在",
            hint="OpenWrt 请确认 logd 正在运行；其他系统可改用 journald（systemd 后端）",
            details={"tried": ["logread", f"/var/log/{name}.log"]},
        )

    # ------------------------------------------------------------------ 工具

    @staticmethod
    def parse_json(raw: str, context: str) -> dict[str, Any]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ToolError(
                ErrorCode.BACKEND_ERROR,
                f"解析 {context} 输出失败：{exc}",
                hint="可能是 ubus 版本差异或输出被截断",
            ) from exc
        if not isinstance(data, dict):
            raise ToolError(
                ErrorCode.BACKEND_ERROR,
                f"{context} 输出不是 JSON 对象",
                hint="检查 ubus 是否可用",
            )
        return data

    @staticmethod
    def is_missing(result: CommandResult) -> bool:
        text = (result.stderr or "").lower()
        return result.exit_status in (127, 126) or "not found" in text or "no such file" in text
