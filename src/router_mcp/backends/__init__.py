"""后端注册表：按 init 系统探测并返回合适的 :class:`ServiceBackend`。"""

from __future__ import annotations

from collections.abc import Sequence

from ..config import SSHConfig
from ..errors import ToolError
from .base import Runner, ServiceBackend
from .initd import InitScriptBackend
from .procd import ProcdBackend
from .systemd import SystemdBackend

BACKEND_CLASSES: dict[str, type[ServiceBackend]] = {
    "procd": ProcdBackend,
    "systemd": SystemdBackend,
    "sysvinit": InitScriptBackend,
}

#: auto 探测顺序
PROBE_ORDER: tuple[str, ...] = ("procd", "systemd", "sysvinit")


def build_backend(name: str, runner: Runner, config: SSHConfig) -> ServiceBackend:
    try:
        cls = BACKEND_CLASSES[name]
    except KeyError as exc:  # pragma: no cover - config 层已校验
        raise ValueError(f"未知后端：{name}") from exc
    return cls(runner, command_timeout=config.limits.command_timeout)


async def resolve_backend(runner: Runner, config: SSHConfig) -> ServiceBackend:
    """根据配置或探测结果返回后端实例。"""
    preferred = config.init_system
    if preferred != "auto":
        backend = build_backend(preferred, runner, config)
        if await backend.detect():
            return backend
        # 显式指定但探测失败：仍然按用户指定执行，错误会在命令层暴露
        return backend

    candidates: Sequence[str] = PROBE_ORDER
    for name in candidates:
        backend = build_backend(name, runner, config)
        try:
            if await backend.detect():
                return backend
        except ToolError:
            # 连接/认证/超时故障不应被静默降级为兜底后端，否则会掩盖真实问题
            raise
        except Exception:  # pragma: no cover - 其他探测异常才切换到下一候选
            continue
    return build_backend("sysvinit", runner, config)


__all__ = [
    "BACKEND_CLASSES",
    "PROBE_ORDER",
    "InitScriptBackend",
    "ProcdBackend",
    "ServiceBackend",
    "SystemdBackend",
    "build_backend",
    "resolve_backend",
]
