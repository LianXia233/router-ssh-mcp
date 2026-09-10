"""MCP 协议层端到端测试：用替身 SSH 通道驱动真实工具函数。"""

from __future__ import annotations

import json
from typing import Any

import pytest

from router_mcp.config import Limits, SSHConfig, SecurityPolicy
from router_mcp.controller import RouterController
from router_mcp.server import create_server, set_controller
from router_mcp.ssh_pool import FakeConnectionManager, FakeScript

from .conftest import PROCD_SCRIPTS, make_controller


def payload(result: Any) -> dict[str, Any]:
    """从 CallToolResult 中取出结构化结果字典。"""
    structured = getattr(result, "structured_content", None)
    if structured:
        data = structured.get("result", structured)
        return data  # type: ignore[no-any-return]
    return json.loads(result.content[0].text)


@pytest.fixture()
def controller():
    controller, runner = make_controller(PROCD_SCRIPTS + RESTART_SCRIPTS)
    set_controller(controller)
    yield controller
    set_controller(None)


RESTART_SCRIPTS = [
    FakeScript(("/etc/init.d/dnsmasq", "restart"), stdout="", exit_status=0),
    FakeScript(
        ("/sbin/logread", "-l", "50", "-e", "dnsmasq"),
        stdout="Mon Sep 10 09:00:00 2026 daemon.info dnsmasq[1]: ready\n",
    ),
]


async def test_tools_annotations() -> None:
    server = create_server()
    tools = {tool.name: tool for tool in await server.list_tools()}
    assert set(tools) == {
        "router_info",
        "service_list",
        "service_status",
        "service_logs",
        "service_start",
        "service_stop",
        "service_restart",
        "run_shell",
    }
    for name in ("router_info", "service_list", "service_status", "service_logs"):
        assert tools[name].annotations.read_only_hint is True
    for name in ("service_start", "service_stop", "service_restart", "run_shell"):
        assert tools[name].annotations.read_only_hint is False
    assert tools["service_restart"].annotations.destructive_hint is True
    assert tools["service_restart"].annotations.idempotent_hint is False
    # run_shell 是高危能力：默认 disabled、需二次确认、非幂等、destructive
    assert tools["run_shell"].annotations.destructive_hint is True
    assert tools["run_shell"].annotations.idempotent_hint is False


async def test_service_list_through_mcp(controller) -> None:
    server = create_server()
    result = await server.call_tool("service_list", {"running_only": True})
    data = payload(result)
    assert data["ok"] is True
    assert data["data"]["init_system"] == "procd"
    assert [item["name"] for item in data["data"]["services"]] == ["dnsmasq"]


async def test_service_status_not_found_through_mcp(controller) -> None:
    server = create_server()
    result = await server.call_tool("service_status", {"name": "ghost"})
    data = payload(result)
    assert data["ok"] is False
    assert data["error"]["code"] == "SERVICE_NOT_FOUND"
    assert data["error"]["hint"]


async def test_invalid_service_name_is_rejected(controller) -> None:
    server = create_server()
    result = await server.call_tool("service_status", {"name": "dnsmasq; reboot"})
    data = payload(result)
    assert data["ok"] is False
    assert data["error"]["code"] == "INVALID_INPUT"


async def test_restart_requires_confirmation_then_succeeds(controller) -> None:
    server = create_server()
    first = payload(await server.call_tool("service_restart", {"name": "dnsmasq"}))
    assert first["ok"] is False
    assert first["error"]["code"] == "CONFIRMATION_REQUIRED"
    assert first["error"]["details"]["expected_confirm"] == "dnsmasq"

    second = payload(
        await server.call_tool("service_restart", {"name": "dnsmasq", "confirm": "dnsmasq"})
    )
    assert second["ok"] is True
    assert second["data"]["action"] == "restart"
    assert second["data"]["command"] == ["/etc/init.d/dnsmasq", "restart"]
    assert second["data"]["state_after"]["running"] is True


async def test_denied_service_write_is_blocked(controller) -> None:
    server = create_server()
    data = payload(
        await server.call_tool("service_restart", {"name": "network", "confirm": "network"})
    )
    assert data["ok"] is False
    assert data["error"]["code"] == "PERMISSION_DENIED"


async def test_logs_through_mcp(controller) -> None:
    server = create_server()
    data = payload(await server.call_tool("service_logs", {"name": "dnsmasq", "lines": 50}))
    assert data["ok"] is True
    assert data["data"]["source"] == "logread"
    assert data["data"]["returned_lines"] == 1


async def test_run_shell_disabled_by_default(controller) -> None:
    server = create_server()
    data = payload(
        await server.call_tool("run_shell", {"command": "echo hi", "confirm": "echo hi"})
    )
    assert data["ok"] is False
    assert data["error"]["code"] == "SHELL_DISABLED"


async def test_run_shell_requires_confirm_then_runs() -> None:
    cfg = SSHConfig(
        host="192.168.1.1",
        port=22,
        username="root",
        password="x",  # noqa: S106 - 测试用
        limits=Limits(command_timeout=5.0),
        security=SecurityPolicy(allow_shell=True, shell_require_confirm=True),
    )
    runner = FakeConnectionManager(raw_scripts=[("uptime", "up 1 day", "", 0)])
    ctrl = RouterController(cfg, runner=runner)
    set_controller(ctrl)
    server = create_server()
    try:
        blocked = payload(await server.call_tool("run_shell", {"command": "uptime"}))
        assert blocked["ok"] is False
        assert blocked["error"]["code"] == "CONFIRMATION_REQUIRED"

        ok = payload(
            await server.call_tool("run_shell", {"command": "uptime", "confirm": "uptime"})
        )
        assert ok["ok"] is True
        assert ok["data"]["stdout"] == "up 1 day"
        assert ok["data"]["confirmed"] is True
        assert runner.raw_calls == ["uptime"]
    finally:
        set_controller(None)
