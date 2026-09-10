"""systemd 后端：systemctl / journalctl。"""

from __future__ import annotations

from typing import Any

from ..commands import (
    journalctl_tail,
    probe_systemd,
    systemctl_action,
    systemctl_list_unit_files,
    systemctl_list_units,
    systemctl_show,
    validate_service_name,
)
from ..errors import ErrorCode, ToolError
from .base import ActionName, ActionResult, LogResult, ServiceBackend, ServiceInfo

SHOW_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "ExecMainPID",
    "ExecMainStartTimestamp",
    "ActiveEnterTimestamp",
    "UnitFileState",
    "Description",
    "FragmentPath",
)


class SystemdBackend(ServiceBackend):
    name = "systemd"

    # ------------------------------------------------------------------ 探测

    async def detect(self) -> bool:
        result = await self._run(probe_systemd())
        return result.exit_status == 0

    # ------------------------------------------------------------------ 解析

    @staticmethod
    def _parse_show(raw: str) -> dict[str, str]:
        props: dict[str, str] = {}
        for line in raw.splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            props[key.strip()] = value.strip()
        return props

    def _info_from_show(self, name: str, props: dict[str, str]) -> ServiceInfo:
        active = props.get("ActiveState", "unknown")
        running = active == "active" if props.get("LoadState") == "loaded" else False
        pid_raw = props.get("ExecMainPID") or "0"
        pid = int(pid_raw) if pid_raw.isdigit() and int(pid_raw) > 0 else None
        unit_state = props.get("UnitFileState") or None
        return ServiceInfo(
            name=name,
            running=running,
            enabled=None if not unit_state else unit_state in {"enabled", "enabled-runtime", "static"},
            pid=pid,
            started_at=props.get("ExecMainStartTimestamp") or props.get("ActiveEnterTimestamp") or None,
            description=props.get("Description") or None,
            source=self.name,
            raw={
                "active_state": active,
                "sub_state": props.get("SubState"),
                "load_state": props.get("LoadState"),
                "unit_file_state": unit_state,
                "fragment_path": props.get("FragmentPath"),
                "unit_id": props.get("Id"),
            },
        )

    async def _show(self, name: str) -> dict[str, str]:
        validate_service_name(name)
        result = await self._run(systemctl_show(name))
        if result.exit_status != 0:
            raise ToolError(
                ErrorCode.COMMAND_FAILED,
                f"systemctl show {name} 失败（退出码 {result.exit_status}）",
                hint="确认 systemd 正常运行且当前用户有查询权限",
                details={"stderr": result.stderr.strip()[:500]},
            )
        return self._parse_show(result.stdout)

    async def _resolve_unit(self, name: str) -> tuple[str, dict[str, str]]:
        """返回实际 unit 名与属性；必要时自动补 .service 后缀。"""
        props = await self._show(name)
        if props.get("LoadState") == "not-found":
            if not name.endswith(".service"):
                alt_name = f"{name}.service"
                alt_props = await self._show(alt_name)
                if alt_props.get("LoadState") != "not-found":
                    return alt_name, alt_props
            raise ToolError(
                ErrorCode.SERVICE_NOT_FOUND,
                f"systemd unit {name!r} 不存在",
                hint="调用 service_list 获取可用 unit 名（通常形如 sshd.service）",
                details={"unit": name},
            )
        return name, props

    async def _enabled_map(self) -> dict[str, bool]:
        result = await self._run(systemctl_list_unit_files())
        mapping: dict[str, bool] = {}
        if result.exit_status != 0:
            return mapping
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            unit, state = parts[0], parts[1]
            mapping[unit] = state in {"enabled", "enabled-runtime", "static"}
        return mapping

    # ------------------------------------------------------------------ 能力

    async def list_services(self, *, with_start_time: bool = False) -> list[ServiceInfo]:
        result = await self._run(systemctl_list_units())
        if result.exit_status != 0:
            raise ToolError(
                ErrorCode.COMMAND_FAILED,
                "systemctl list-units 调用失败",
                hint="确认 systemd 正在运行且当前用户有权限查询",
                details={"stderr": result.stderr.strip()[:500]},
            )
        try:
            import json

            units = json.loads(result.stdout)
        except ValueError:
            units = None
        if units is None:
            units = []
            for line in result.stdout.splitlines():
                parts = line.split(maxsplit=4)
                if len(parts) < 4:
                    continue
                units.append(
                    {
                        "unit": parts[0],
                        "load": parts[1],
                        "active": parts[2],
                        "sub": parts[3],
                        "description": parts[4] if len(parts) > 4 else "",
                    }
                )

        enabled = await self._enabled_map()
        services: list[ServiceInfo] = []
        for unit in units:
            name = str(unit.get("unit") or "")
            if not name:
                continue
            state = str(unit.get("active") or "unknown")
            services.append(
                ServiceInfo(
                    name=name,
                    running=state == "active",
                    enabled=enabled.get(name),
                    pid=None,
                    started_at=None,
                    description=unit.get("description") or None,
                    source=self.name,
                    raw={"active": state, "sub": unit.get("sub"), "load": unit.get("load")},
                )
            )
        return sorted(services, key=lambda item: item.name)

    async def status(self, name: str) -> ServiceInfo:
        unit, props = await self._resolve_unit(name)
        info = self._info_from_show(unit, props)
        if info.pid and not info.started_at:
            info.started_at = await self._proc_start_epoch(info.pid)
        return info

    async def action(self, name: str, action: ActionName) -> ActionResult:
        unit, props = await self._resolve_unit(name)
        before = self._info_from_show(unit, props)
        result = await self._run(systemctl_action(unit, action), timeout=self.command_timeout * 2)
        if result.exit_status != 0:
            stderr = result.stderr.lower()
            if "access denied" in stderr or "authentication" in stderr:
                raise ToolError(
                    ErrorCode.PERMISSION_DENIED,
                    f"systemctl {action} {unit} 被拒绝",
                    hint="非 root 用户需要 polkit 授权或 sudo 规则；建议在路由器上以 root 连接",
                    details={"stderr": result.stderr.strip()[:500]},
                )
            raise ToolError(
                ErrorCode.COMMAND_FAILED,
                f"systemctl {action} {unit} 失败（退出码 {result.exit_status}）",
                hint="查看 stderr 定位原因；可先用 service_logs 查看该 unit 日志",
                details={
                    "unit": unit,
                    "action": action,
                    "exit_status": result.exit_status,
                    "stderr": result.stderr.strip()[:500],
                },
            )
        after = self._info_from_show(unit, await self._show(unit))
        return ActionResult(
            name=unit,
            action=action,
            exit_status=result.exit_status,
            command=result.argv,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_ms=result.duration_ms,
            state_before=before,
            state_after=after,
        )

    async def logs(self, name: str, lines: int) -> LogResult:
        unit, _ = await self._resolve_unit(name)
        result = await self._run(journalctl_tail(unit, lines))
        if result.exit_status != 0 or not result.stdout.strip():
            stderr = (result.stderr or "").lower()
            if "no journal files" in stderr or not stderr:
                raise ToolError(
                    ErrorCode.UNSUPPORTED_ACTION,
                    f"journald 中没有 {unit} 的日志",
                    hint="确认 journald 已启用持久化（Storage=persistent）或该服务曾产生输出",
                    details={"unit": unit, "stderr": result.stderr.strip()[:300]},
                )
            raise ToolError(
                ErrorCode.COMMAND_FAILED,
                f"journalctl 读取 {unit} 日志失败（退出码 {result.exit_status}）",
                hint="确认 journalctl 可用且当前用户在 systemd-journal 组",
                details={"stderr": result.stderr.strip()[:500]},
            )
        return LogResult(
            name=unit,
            lines=result.stdout.splitlines()[-lines:],
            requested_lines=lines,
            source="journalctl",
            command=result.argv,
        )
