"""测试夹具：提供离线的假 SSH 通道与可注入的控制器。"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from router_mcp.config import Limits, SSHConfig, SecurityPolicy
from router_mcp.controller import RouterController
from router_mcp.ssh_pool import FakeConnectionManager, FakeScript

UBUS_OUTPUT = json.dumps(
    {
        "dnsmasq": {
            "instances": {
                "cfg01411c": {
                    "running": True,
                    "pid": 2814,
                    "command": ["/usr/sbin/dnsmasq", "-C", "/var/etc/dnsmasq.conf"],
                    "respawn": {"threshold": 3600, "timeout": 5, "retry": 5},
                }
            },
            "triggers": [],
        },
        "odhcpd": {"instances": {"instance1": {"running": False, "pid": 0}}},
    }
)

PROCD_SCRIPTS = [
    FakeScript(("/bin/cat", "/proc/1/comm"), stdout="procd\n"),
    FakeScript(("/sbin/ubus", "call", "service", "list"), stdout=UBUS_OUTPUT),
    FakeScript(("/bin/ls", "-1", "/etc/rc.d"), stdout="S19dnsmasq\nK89odhcpd\n"),
    FakeScript(("/bin/ls", "-1", "/etc/init.d"), stdout="dnsmasq\nodhcpd\nnetwork\n"),
    FakeScript(("/bin/uname", "-a"), stdout="Linux OpenWrt 6.6.73 #0 SMP\n"),
    FakeScript(
        ("/bin/cat", "/etc/openwrt_release"),
        stdout='DISTRIB_ID="OpenWrt"\nDISTRIB_RELEASE="24.10.0"\n',
    ),
]

SYSTEMD_SHOW = (
    "Id=sshd.service\n"
    "LoadState=loaded\n"
    "ActiveState=active\n"
    "SubState=running\n"
    "ExecMainPID=1234\n"
    "ExecMainStartTimestamp=Thu 2026-09-10 09:00:00 CST\n"
    "UnitFileState=enabled\n"
    "Description=OpenSSH Daemon\n"
    "FragmentPath=/lib/systemd/system/sshd.service\n"
)

SYSTEMD_SCRIPTS = [
    FakeScript(("/bin/test", "-d", "/run/systemd/system"), exit_status=0, stdout=""),
    FakeScript(
        ("/bin/systemctl", "list-units"),
        stdout=json.dumps(
            [
                {
                    "unit": "sshd.service",
                    "load": "loaded",
                    "active": "active",
                    "sub": "running",
                    "description": "OpenSSH Daemon",
                },
                {
                    "unit": "nginx.service",
                    "load": "loaded",
                    "active": "inactive",
                    "sub": "dead",
                    "description": "nginx",
                },
            ]
        ),
    ),
    FakeScript(
        ("/bin/systemctl", "list-unit-files"),
        stdout="sshd.service enabled\nnginx.service disabled\n",
    ),
    FakeScript(("/bin/systemctl", "show", "sshd.service"), stdout=SYSTEMD_SHOW),
    FakeScript(
        ("/bin/systemctl", "show", "missing.service"),
        stdout="LoadState=not-found\nActiveState=inactive\n",
    ),
]


def make_config(
    *,
    allowed: tuple[str, ...] = (),
    denied: tuple[str, ...] = ("network", "firewall"),
    require_confirm: bool = True,
    init_system: str = "auto",
) -> SSHConfig:
    return SSHConfig(
        host="192.168.1.1",
        port=22,
        username="root",
        password="secret",  # noqa: S106 - 测试用
        init_system=init_system,
        limits=Limits(command_timeout=5.0, max_log_lines=200),
        security=SecurityPolicy(
            require_confirmation=require_confirm,
            allowed_services=allowed,
            denied_services=denied,
        ),
    )


def make_controller(scripts: list[FakeScript] | None = None, **config_kwargs: Any) -> tuple[RouterController, FakeConnectionManager]:
    runner = FakeConnectionManager(scripts=list(scripts or PROCD_SCRIPTS))
    controller = RouterController(make_config(**config_kwargs), runner=runner)
    return controller, runner


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """隔离环境变量，避免本机配置影响测试。"""
    for key in list(os.environ):
        if key.startswith("ROUTER_MCP_"):
            monkeypatch.delenv(key, raising=False)
