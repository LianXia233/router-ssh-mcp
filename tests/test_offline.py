"""离线单元测试：命令白名单、配置、解析、安全策略与错误映射（不需要真实设备）。"""

from __future__ import annotations

import json
from typing import Any

import pytest

from router_mcp import commands as cmd
from router_mcp.config import load_config
from router_mcp.controller import RouterController
from router_mcp.errors import ErrorCode, ToolError
from router_mcp.programs import ProgramResolver
from router_mcp.ssh_pool import FakeConnectionManager, FakeScript, render_command

from .conftest import PROCD_SCRIPTS, SYSTEMD_SCRIPTS, make_config, make_controller


# --------------------------------------------------------------------- 白名单


@pytest.mark.parametrize(
    "name",
    [
        "dnsmasq",
        "AdGuardHome",
        "sshd.service",
        "luci-app-foo",
        "x@instance",
    ],
)
def test_valid_service_names(name: str) -> None:
    assert cmd.validate_service_name(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        "   ",
        "dnsmasq; rm -rf /",
        "../../etc/init.d/dnsmasq",
        "dnsmasq && reboot",
        "$(reboot)",
        "a|b",
        "svc name",
        "svc\nname",
        "/etc/init.d/dnsmasq",
        ".hidden",
        "a" * 65,
    ],
)
def test_rejected_service_names(name: str) -> None:
    with pytest.raises(ToolError) as excinfo:
        cmd.validate_service_name(name)
    assert excinfo.value.code in {ErrorCode.INVALID_INPUT}


def test_command_spec_is_argv_and_never_shell() -> None:
    spec = cmd.init_d_action("dnsmasq", "restart")
    assert spec.argv == ("/etc/init.d/dnsmasq", "restart")
    assert spec.category == "write"
    assert ";" not in " ".join(spec.argv)


def test_path_whitelist() -> None:
    spec = cmd.list_dir("/etc/init.d")
    assert spec.program == "ls"
    # 占位符在执行前会被解析为真实路径
    assert spec.with_program_path("/bin/ls").argv == ("/bin/ls", "-1", "/etc/init.d")
    with pytest.raises(ToolError):
        cmd.list_dir("/etc/shadow")


def test_lines_bound() -> None:
    assert cmd.validate_lines(10, 500) == 10
    with pytest.raises(ToolError) as exc:
        cmd.validate_lines(0, 500)
    assert exc.value.code is ErrorCode.INVALID_INPUT
    with pytest.raises(ToolError):
        cmd.validate_lines(501, 500)


# --------------------------------------------------------------------- 命令渲染与路径解析


def test_render_command_escapes_shell_metacharacters() -> None:
    """第二道防线：参数一律经 POSIX 转义后才拼成命令串。"""
    rendered = render_command(["/bin/cat", "/etc/init.d/x; rm -rf /"])
    assert rendered == "/bin/cat '/etc/init.d/x; rm -rf /'"
    assert render_command(["/bin/echo", "$(reboot)", "a|b", "`id`"]) == (
        "/bin/echo '$(reboot)' 'a|b' '`id`'"
    )
    # 含空格的 JSON 参数必须作为整体传递
    assert render_command(["/bin/ubus", "call", "service", "list", '{"name": "dnsmasq"}']) == (
        "/bin/ubus call service list '{\"name\": \"dnsmasq\"}'"
    )


async def test_program_resolver_prefers_existing_path() -> None:
    runner = FakeConnectionManager(
        scripts=[
            FakeScript(("/bin/test", "-x", "/bin/test"), exit_status=0),
            FakeScript(("/bin/test", "-x", "/sbin/ubus"), exit_status=1),
            FakeScript(("/bin/test", "-x", "/bin/ubus"), exit_status=0),
        ]
    )
    resolver = ProgramResolver(runner)
    assert await resolver.resolve("ubus") == "/bin/ubus"
    assert resolver.snapshot()["ubus"] == "/bin/ubus"


async def test_program_resolver_falls_back_without_probe() -> None:
    """探测不可用时回退首个候选，保证离线替身环境仍可运行。"""
    assert await ProgramResolver(FakeConnectionManager(scripts=[])).resolve("ubus") == "/sbin/ubus"


# --------------------------------------------------------------------- 配置


def test_config_requires_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ROUTER_MCP_PASSWORD", raising=False)
    monkeypatch.delenv("ROUTER_MCP_KEY_PATH", raising=False)
    with pytest.raises(ToolError) as exc:
        load_config()
    assert exc.value.code is ErrorCode.CONFIG_ERROR


def test_config_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ROUTER_MCP_HOST", "10.0.0.1")
    monkeypatch.setenv("ROUTER_MCP_PORT", "2222")
    monkeypatch.setenv("ROUTER_MCP_USER", "admin")
    monkeypatch.setenv("ROUTER_MCP_PASSWORD", "pw")
    monkeypatch.setenv("ROUTER_MCP_COMMAND_TIMEOUT", "30")
    monkeypatch.setenv("ROUTER_MCP_REQUIRE_CONFIRM", "false")
    cfg = load_config()
    assert (cfg.host, cfg.port, cfg.username) == ("10.0.0.1", 2222, "admin")
    assert cfg.limits.command_timeout == 30.0
    assert cfg.security.require_confirmation is False


def test_config_redacted_never_leaks_password() -> None:
    cfg = make_config()
    snapshot = json.dumps(cfg.redacted(), ensure_ascii=False)
    assert "secret" not in snapshot
    assert cfg.redacted()["auth_method"] == "password"


# --------------------------------------------------------------------- procd


async def test_procd_list_and_status() -> None:
    controller, runner = make_controller()
    services, init_system, _ = await controller.list_services()
    assert init_system == "procd"
    dnsmasq = next(item for item in services if item["name"] == "dnsmasq")
    assert dnsmasq["running"] is True
    assert dnsmasq["pid"] == 2814
    assert dnsmasq["enabled"] is True
    assert dnsmasq["source"] == "procd"

    status = await controller.status("dnsmasq")
    assert status["service"]["pid"] == 2814
    assert status["service"]["started_at"] is None  # 无 /proc 数据时留空


async def test_procd_status_not_found() -> None:
    controller, _ = make_controller()
    with pytest.raises(ToolError) as exc:
        await controller.status("nope")
    assert exc.value.code is ErrorCode.SERVICE_NOT_FOUND
    assert "available_count" in exc.value.details


async def test_procd_logs_via_logread() -> None:
    scripts = PROCD_SCRIPTS + [
        FakeScript(
            ("/sbin/logread", "-l", "20", "-e", "dnsmasq"),
            stdout="Mon Sep 10 09:00:00 2026 daemon.info dnsmasq[1]: started\n",
        )
    ]
    controller, _ = make_controller(scripts)
    logs = await controller.logs("dnsmasq", 20)
    assert logs["source"] == "logread"
    assert logs["returned_lines"] == 1


async def test_procd_logs_fallback_to_local_filter() -> None:
    scripts = PROCD_SCRIPTS + [
        FakeScript(("/sbin/logread", "-l", "50"), stdout="foo bar\ndnsmasq line 1\ndnsmasq line 2\n"),
    ]
    controller, _ = make_controller(scripts)
    logs = await controller.logs("dnsmasq", 10)
    assert logs["source"] == "logread(filtered)"
    assert all("dnsmasq" in line for line in logs["lines"])


# --------------------------------------------------------------------- systemd


async def test_systemd_detection_and_list() -> None:
    controller, _ = make_controller(SYSTEMD_SCRIPTS)
    services, init_system, _ = await controller.list_services()
    assert init_system == "systemd"
    names = {item["name"] for item in services}
    assert {"sshd.service", "nginx.service"} <= names
    sshd = next(item for item in services if item["name"] == "sshd.service")
    assert sshd["running"] is True and sshd["enabled"] is True


async def test_systemd_status_and_missing_unit() -> None:
    controller, _ = make_controller(SYSTEMD_SCRIPTS)
    status = await controller.status("sshd.service")
    assert status["service"]["pid"] == 1234
    assert status["service"]["started_at"].startswith("Thu 2026-09-10")

    with pytest.raises(ToolError) as exc:
        await controller.status("missing.service")
    assert exc.value.code is ErrorCode.SERVICE_NOT_FOUND


async def test_systemd_logs() -> None:
    scripts = SYSTEMD_SCRIPTS + [
        FakeScript(
            ("/bin/journalctl", "-u", "sshd.service"),
            stdout="2026-09-10T09:00:00+0800 host sshd[1]: ready\n",
        )
    ]
    controller, _ = make_controller(scripts)
    logs = await controller.logs("sshd.service", 50)
    assert logs["source"] == "journalctl"


# --------------------------------------------------------------------- 安全策略


async def test_write_requires_confirmation() -> None:
    controller, _ = make_controller()
    with pytest.raises(ToolError) as exc:
        await controller.perform_action("dnsmasq", "restart", confirm=None)
    assert exc.value.code is ErrorCode.CONFIRMATION_REQUIRED
    assert exc.value.details["expected_confirm"] == "dnsmasq"

    with pytest.raises(ToolError):
        await controller.perform_action("dnsmasq", "restart", confirm="dnsmas")


async def test_confirmation_can_be_disabled() -> None:
    scripts = PROCD_SCRIPTS + [
        FakeScript(("/etc/init.d/dnsmasq", "restart"), stdout="", exit_status=0),
    ]
    controller, _ = make_controller(scripts, require_confirm=False)
    result = await controller.perform_action("dnsmasq", "restart", confirm=None)
    assert result["exit_status"] == 0
    assert result["state_after"]["running"] is True


async def test_denied_service_blocked_for_write_only() -> None:
    controller, _ = make_controller()
    with pytest.raises(ToolError) as exc:
        await controller.perform_action("network", "restart", confirm="network")
    assert exc.value.code is ErrorCode.PERMISSION_DENIED
    # 只读仍允许
    status = await controller.status("network")
    assert status["service"]["name"] == "network"


async def test_allowed_services_whitelist() -> None:
    controller, _ = make_controller(allowed=("dnsmasq",))
    with pytest.raises(ToolError) as exc:
        await controller.status("odhcpd")
    assert exc.value.code is ErrorCode.PERMISSION_DENIED


async def test_action_failure_returns_command_failed() -> None:
    scripts = PROCD_SCRIPTS + [
        FakeScript(("/etc/init.d/dnsmasq", "start"), exit_status=1, stderr="syntax error"),
    ]
    controller, _ = make_controller(scripts)
    with pytest.raises(ToolError) as exc:
        await controller.perform_action("dnsmasq", "start", confirm="dnsmasq")
    assert exc.value.code is ErrorCode.COMMAND_FAILED
    assert "syntax error" in exc.value.details["stderr"]


# --------------------------------------------------------------------- 错误映射


async def test_command_timeout_is_structured() -> None:
    runner = FakeConnectionManager(
        scripts=[FakeScript(("/bin/cat", "/proc/1/comm"), stdout="procd\n", delay=2.0)]
    )
    spec = cmd.read_file("/proc/1/comm").with_program_path("/bin/cat")
    with pytest.raises(ToolError) as exc:
        await runner.run(spec, timeout=0.2)
    assert exc.value.code is ErrorCode.COMMAND_TIMEOUT
    assert "超时" in exc.value.message
    assert exc.value.details["timeout"] == 0.2


async def test_unknown_command_exit_127_is_surfaced() -> None:
    controller, _ = make_controller(PROCD_SCRIPTS)
    data = await controller.status("network")  # 该服务无 procd 实例
    assert data["service"]["running"] is False or data["service"]["running"] is None


async def test_connection_failure_is_not_silently_downgraded() -> None:
    """连接/认证失败必须向上冒泡，不能被兜底后端掩盖。"""

    class BrokenRunner:
        async def run(self, spec, *, timeout=None):  # noqa: ANN001
            raise ToolError(
                ErrorCode.CONNECTION_FAILED,
                "连接 root@10.0.0.9:22 超时（>3.0s）",
                hint="确认主机在线",
            )

        async def health(self) -> dict[str, Any]:
            return {"connected": False}

    controller = RouterController(make_config(), runner=BrokenRunner())  # type: ignore[arg-type]
    with pytest.raises(ToolError) as exc:
        await controller.init_system()
    assert exc.value.code is ErrorCode.CONNECTION_FAILED


async def test_router_info_shape() -> None:
    controller, _ = make_controller()
    info = await controller.info()
    assert info["backend"] == "procd"
    assert info["ssh"]["connected"] is True
    assert info["device"]["release_source"] == "/etc/openwrt_release"
    assert "secret" not in json.dumps(info, ensure_ascii=False)
