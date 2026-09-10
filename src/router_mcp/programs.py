"""程序路径解析。

OpenWrt / ImmortalWrt / Debian 等系统的程序路径并不一致（例如 ubus 在部分固件上
位于 /bin/ubus，在另一些上位于 /sbin/ubus；systemctl 常见于 /usr/bin/systemctl）。
本模块在首次使用时用 ``test -x`` 按候选顺序探测真实路径并缓存，探测不到时回退
首个候选（离线自测替身就走这条路径）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .commands import PROGRAM_CANDIDATES, CommandSpec
from .errors import ErrorCode, ToolError


@runtime_checkable
class SupportsRun(Protocol):
    """最小执行接口，避免与后端模块产生循环导入。"""

    async def run(self, spec: CommandSpec, *, timeout: float | None = None) -> object: ...


def probe_spec(program: str, target: str) -> CommandSpec:
    """构造 ``<test> -x <target>`` 探测命令。"""
    return CommandSpec(
        template="probe_program",
        argv=(program, "-x", target),
        category="read",
        description=f"探测 {target} 是否存在且可执行",
    )


@dataclass
class ProgramResolver:
    """按候选路径探测真实程序路径，结果按 key 缓存。"""

    runner: SupportsRun
    cache: dict[str, str] = field(default_factory=dict)
    _test_path: str | None = field(default=None, init=False)
    _test_probed: bool = field(default=False, init=False)

    async def _find_test(self) -> str | None:
        """先定位 test 自身（其余探测依赖它）。"""
        if self._test_probed:
            return self._test_path
        self._test_probed = True
        for candidate in PROGRAM_CANDIDATES["test"]:
            try:
                result = await self.runner.run(probe_spec(candidate, candidate))
            except Exception:  # noqa: BLE001 - 探测失败即换下一个候选
                continue
            if getattr(result, "exit_status", 1) == 0:
                self._test_path = candidate
                break
        return self._test_path

    async def resolve(self, key: str) -> str:
        """返回该程序的可执行路径；探测失败时回退首个候选。"""
        if key in self.cache:
            return self.cache[key]
        candidates = PROGRAM_CANDIDATES.get(key)
        if not candidates:
            raise ToolError(
                ErrorCode.BLOCKED_COMMAND,
                f"未登记的程序标识：{key}",
                hint="这是实现缺陷，请提交 issue",
            )
        path = candidates[0]
        test = await self._find_test()
        if test:
            for candidate in candidates:
                try:
                    result = await self.runner.run(probe_spec(test, candidate))
                except Exception:  # noqa: BLE001
                    break
                if getattr(result, "exit_status", 1) == 0:
                    path = candidate
                    break
        self.cache[key] = path
        return path

    def snapshot(self) -> dict[str, str]:
        """已解析路径快照，便于排障输出。"""
        return dict(self.cache)
