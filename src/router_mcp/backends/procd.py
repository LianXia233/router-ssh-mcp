"""OpenWrt / procd 后端：通过 ubus 获取权威服务状态。"""

from __future__ import annotations

from typing import Any

from ..commands import init_d_action, ubus_service_list
from ..errors import ErrorCode, ToolError
from .base import ServiceInfo
from .initd import InitScriptBackend


class ProcdBackend(InitScriptBackend):
    """procd 主机：``ubus call service list`` 提供实例级状态（running/pid）。"""

    name = "procd"

    async def detect(self) -> bool:
        comm = await self._read_text("/proc/1/comm")
        if comm == "procd":
            return True
        return comm == "init" and await super().detect()

    # ------------------------------------------------------------------ 解析

    def _parse_entry(self, name: str, payload: dict[str, Any]) -> ServiceInfo:
        instances: dict[str, Any] = payload.get("instances") or {}
        running: bool | None = None
        pid: int | None = None
        command: str | None = None

        if instances:
            alive = [inst for inst in instances.values() if inst.get("running")]
            running = bool(alive)
            for inst in alive or list(instances.values()):
                if inst.get("pid"):
                    pid = int(inst["pid"])
                    break
            first_cmd = next(
                (inst.get("command") for inst in (alive or instances.values()) if inst.get("command")),
                None,
            )
            if isinstance(first_cmd, list):
                command = " ".join(str(part) for part in first_cmd)

        return ServiceInfo(
            name=name,
            running=running,
            enabled=None,  # 由 enabled_map 补齐
            pid=pid,
            started_at=None,
            source=self.name,
            description=command,
            raw={
                "instances": sorted(instances.keys()),
                "instance_count": len(instances),
                "triggers": bool(payload.get("triggers")),
            },
        )

    async def _ubus_entries(self, name: str | None = None) -> dict[str, ServiceInfo]:
        result = await self._run(ubus_service_list(name))
        if result.exit_status != 0 or not result.stdout.strip():
            return {}
        if self.is_missing(result):
            return {}
        data = self.parse_json(result.stdout, "ubus service list")
        entries: dict[str, ServiceInfo] = {}
        for svc_name, payload in data.items():
            if isinstance(payload, dict):
                entries[svc_name] = self._parse_entry(svc_name, payload)
        return entries

    # ------------------------------------------------------------------ 能力

    async def list_services(self, *, with_start_time: bool = False) -> list[ServiceInfo]:
        entries = await self._ubus_entries()
        enabled = await self.enabled_map()
        scripts = await self.init_scripts()

        merged: dict[str, ServiceInfo] = {}
        for svc_name, info in entries.items():
            info.enabled = enabled.get(svc_name)
            merged[svc_name] = info
        for script in scripts:
            if script in merged:
                continue
            merged[script] = ServiceInfo(
                name=script,
                running=False,
                enabled=enabled.get(script),
                source="init.d",
                description="存在 init 脚本但当前无 procd 实例",
            )

        if with_start_time:
            for info in merged.values():
                if info.running and info.pid:
                    info.started_at = await self._proc_start_epoch(info.pid)
        return sorted(merged.values(), key=lambda item: item.name)

    async def status(self, name: str) -> ServiceInfo:
        await self.require_script(name)
        entries = await self._ubus_entries(name)
        if name in entries:
            info = entries[name]
            info.enabled = (await self.enabled_map()).get(name)
            info.started_at = await self._proc_start_epoch(info.pid) if info.pid else None
            return info

        # 未被 procd 管理的脚本：退回 init.d status
        result = await self._run(init_d_action(name, "status"))
        if result.exit_status == 0:
            info = ServiceInfo(
                name=name,
                running=True,
                enabled=(await self.enabled_map()).get(name),
                source="init.d",
                description=(result.stdout or result.stderr).strip() or None,
                raw={"status_exit_code": result.exit_status},
            )
            return info
        return ServiceInfo(
            name=name,
            running=False,
            enabled=(await self.enabled_map()).get(name),
            source="init.d",
            description=(result.stdout or result.stderr).strip() or "服务未运行",
            raw={"status_exit_code": result.exit_status},
        )
