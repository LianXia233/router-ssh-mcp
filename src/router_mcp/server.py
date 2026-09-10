"""MCP 服务器与工具注册。

工具一览（annotations 标注读写属性，供客户端做权限提示）：
    只读：router_info / service_list / service_status / service_logs
    写入：service_start / service_stop / service_restart（需二次确认）
    高危：run_shell（默认关闭，需 ROUTER_MCP_ALLOW_SHELL=true 启用，且需二次确认）
"""

from __future__ import annotations

import time
from typing import Any

from ._compat import MCPServer, READ_ONLY, WRITE_RESTART, WRITE_START, WRITE_STOP, annotations
from .config import SSHConfig, load_config
from .controller import RouterController
from .models import (
    ErrorResult,
    RouterInfoData,
    RouterInfoResult,
    ServiceActionData,
    ServiceActionResult,
    ServiceEntry,
    ServiceListData,
    ServiceListResult,
    ServiceLogsData,
    ServiceLogsResult,
    ServiceStatusData,
    ServiceStatusResult,
    ShellData,
    ShellResult,
    error_result,
    payload_from_error,
)

SERVER_NAME = "router-ssh-mcp"

#: 连接器自我描述：供 MCP 客户端（如 WorkBuddy 连接器管理）识别其本质与能力边界。
CONNECTOR_DESCRIPTION = (
    "通过 SSH 管理路由器（OpenWrt/ImmortalWrt/systemd）服务的 MCP 连接器；"
    "支持按设备自定义 IP、账号与密码/密钥；只读工具可直接调用，"
    "写入操作需二次确认，run_shell 高危能力默认关闭。"
)

_controller: RouterController | None = None


def get_controller(config: SSHConfig | None = None) -> RouterController:
    """获取（或惰性创建）控制器单例。"""
    global _controller
    if _controller is None:
        _controller = RouterController(config or load_config())
    return _controller


def set_controller(controller: RouterController | None) -> None:
    """替换控制器，供测试与自测脚本注入替身。"""
    global _controller
    _controller = controller


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _host_of(controller: RouterController) -> str:
    return controller.config.host


def create_server(config: SSHConfig | None = None) -> MCPServer:
    """构建 MCP 服务器实例。"""
    mcp = MCPServer(
        SERVER_NAME,
        instructions=(
            "通过 SSH 管理路由器上的服务（OpenWrt/procd 与 systemd 均可）。"
            "本连接器能力标识为 ssh-router-management：只读工具可直接调用；"
            "start/stop/restart 属于写入操作，需传入 confirm=<服务名> 二次确认。"
            "高危服务（network/firewall 等）默认拒绝写入。"
            "run_shell 是可选的高危能力：默认关闭，需设置 ROUTER_MCP_ALLOW_SHELL=true 才会启用，"
            "且调用时必须把 confirm 设为命令本身的完整字符串进行二次确认；默认拦截 rm -rf、mkfs、dd 等高危命令。"
        ),
    )

    # ---------------------------------------------------------------- 只读工具

    @mcp.tool(annotations=annotations(**READ_ONLY, title="路由器连接与设备信息"))
    async def router_info() -> RouterInfoResult | ErrorResult:
        """查询 SSH 连接健康状态、探测到的 init 系统、设备系统与生效的安全策略。

        返回结构：
            {"ok": true, "tool": "router_info", "host": "...", "data": {
                "host", "port", "username", "backend",
                "ssh": {"connected", "reuse_count", "reconnect_count", "server_version", ...},
                "device": {"uname", "release", "release_source"},
                "security": {...}, "limits": {...}}}
        """
        started = time.perf_counter()
        controller = get_controller(config)
        try:
            data = await controller.info()
        except Exception as exc:  # noqa: BLE001
            return error_result(
                "router_info", _host_of(controller), payload_from_error(exc), _elapsed_ms(started)
            )
        return RouterInfoResult(
            ok=True,
            tool="router_info",
            host=_host_of(controller),
            duration_ms=_elapsed_ms(started),
            data=RouterInfoData(**data),
        )

    @mcp.tool(annotations=annotations(**READ_ONLY, title="列出服务"))
    async def service_list(
        name_filter: str | None = None,
        running_only: bool = False,
        with_start_time: bool = False,
    ) -> ServiceListResult | ErrorResult:
        """列出路由器上的服务及其运行状态。

        参数：
            name_filter: 按名称子串过滤（大小写不敏感），可选
            running_only: 仅返回运行中的服务
            with_start_time: 额外读取每个服务的启动时间（命令数随服务数增加，默认关闭）

        返回结构：
            {"ok": true, "data": {"services": [{"name", "running", "enabled",
              "pid", "started_at", "description", "source"}], "count", "running_count",
              "init_system", "host", "warnings"}}
        """
        started = time.perf_counter()
        controller = get_controller(config)
        try:
            services, init_system, warnings = await controller.list_services(
                name_filter=name_filter,
                running_only=running_only,
                with_start_time=with_start_time,
            )
        except Exception as exc:  # noqa: BLE001
            return error_result(
                "service_list", _host_of(controller), payload_from_error(exc), _elapsed_ms(started)
            )
        entries = [ServiceEntry(**{k: v for k, v in svc.items() if k != "raw"}) for svc in services]
        return ServiceListResult(
            ok=True,
            tool="service_list",
            host=_host_of(controller),
            duration_ms=_elapsed_ms(started),
            data=ServiceListData(
                services=entries,
                count=len(entries),
                running_count=sum(1 for item in entries if item.running is True),
                init_system=init_system,
                host=_host_of(controller),
                warnings=warnings,
            ),
        )

    @mcp.tool(annotations=annotations(**READ_ONLY, title="查询服务状态"))
    async def service_status(name: str) -> ServiceStatusResult | ErrorResult:
        """查询单个服务的运行状态、PID、启动时间与开机自启状态。

        参数：
            name: 服务名（OpenWrt 为 /etc/init.d 脚本名，systemd 为 unit 名，如 sshd.service）

        返回结构：
            {"ok": true, "data": {"service": {"name", "running", "enabled", "pid",
              "started_at", "description", "source"}, "checked_at", "init_system"}}

        服务不存在时返回 ok=false，error.code = SERVICE_NOT_FOUND，并在 details 中给出可用服务样例。
        """
        started = time.perf_counter()
        controller = get_controller(config)
        try:
            data = await controller.status(name)
        except Exception as exc:  # noqa: BLE001
            return error_result(
                "service_status", _host_of(controller), payload_from_error(exc), _elapsed_ms(started)
            )
        service = data["service"]
        return ServiceStatusResult(
            ok=True,
            tool="service_status",
            host=_host_of(controller),
            duration_ms=_elapsed_ms(started),
            data=ServiceStatusData(
                service=ServiceEntry(**{k: v for k, v in service.items() if k != "raw"}),
                checked_at=data["checked_at"],
            ),
        )

    @mcp.tool(annotations=annotations(**READ_ONLY, title="查看服务日志"))
    async def service_logs(name: str, lines: int = 50) -> ServiceLogsResult | ErrorResult:
        """读取服务日志尾部内容（OpenWrt 走 logread，systemd 走 journalctl）。

        参数：
            name: 服务名
            lines: 返回行数，1 <= lines <= ROUTER_MCP_MAX_LOG_LINES（默认 500）

        返回结构：
            {"ok": true, "data": {"name", "requested_lines", "returned_lines",
              "source", "command", "truncated", "lines": [...] }}
        """
        started = time.perf_counter()
        controller = get_controller(config)
        try:
            data = await controller.logs(name, lines)
        except Exception as exc:  # noqa: BLE001
            return error_result(
                "service_logs", _host_of(controller), payload_from_error(exc), _elapsed_ms(started)
            )
        return ServiceLogsResult(
            ok=True,
            tool="service_logs",
            host=_host_of(controller),
            duration_ms=_elapsed_ms(started),
            data=ServiceLogsData(**data),
        )

    # ---------------------------------------------------------------- 写入工具

    @mcp.tool(annotations=annotations(**WRITE_START, title="启动服务"))
    async def service_start(name: str, confirm: str | None = None) -> ServiceActionResult | ErrorResult:
        """启动指定服务（写入操作，需二次确认）。

        参数：
            name: 服务名
            confirm: 必须等于服务名才真正执行；否则返回 error.code = CONFIRMATION_REQUIRED

        返回结构：
            {"ok": true, "data": {"name", "action", "exit_status", "command",
              "stdout", "stderr", "duration_ms", "state_before", "state_after"}}
        """
        return await _run_action(config, name, "start", confirm)

    @mcp.tool(annotations=annotations(**WRITE_STOP, title="停止服务"))
    async def service_stop(name: str, confirm: str | None = None) -> ServiceActionResult | ErrorResult:
        """停止指定服务（写入操作，需二次确认）。

        参数与返回结构同 service_start。注意停止 ssh/dropbear 会导致连接中断。
        """
        return await _run_action(config, name, "stop", confirm)

    @mcp.tool(annotations=annotations(**WRITE_RESTART, title="重启服务"))
    async def service_restart(name: str, confirm: str | None = None) -> ServiceActionResult | ErrorResult:
        """重启指定服务（写入操作，需二次确认）。

        参数与返回结构同 service_start。restart 非幂等，重复调用会重复中断服务。
        """
        return await _run_action(config, name, "restart", confirm)

    # ---------------------------------------------------------------- 高危工具

    @mcp.tool(annotations=annotations(read_only=False, destructive=True, idempotent=False, title="执行任意 Shell 命令"))
    async def run_shell(command: str, confirm: str | None = None) -> ShellResult | ErrorResult:
        """在路由器上执行任意 shell 命令（高危能力，默认关闭，需二次确认）。

        安全约束（任意一条不满足都会返回错误而非执行）：
            * 必须设置 ROUTER_MCP_ALLOW_SHELL=true 才会启用，否则返回 error.code = SHELL_DISABLED；
            * 默认拦截高危命令（rm -rf / mkfs / dd if= / 写入 /dev/* / fork 炸弹 / 管道进 shell 等），
              命中时返回 error.code = BLOCKED_COMMAND；
            * 需把 confirm 设为命令本身的完整字符串进行二次确认，否则返回 CONFIRMATION_REQUIRED；
            * 命令以 root 身份在远端登录 shell 中执行，会绕过服务白名单，请谨慎使用。

        参数：
            command: 要执行的 shell 命令字符串
            confirm: 必须等于 command 的完整内容（含空格与引号）才真正执行

        返回结构：
            {"ok": true, "data": {"raw_command", "exit_status", "stdout", "stderr",
              "duration_ms", "host", "reused_connection", "denied", "confirmed", "warning"}}
        """
        started = time.perf_counter()
        controller = get_controller(config)
        try:
            data = await controller.run_shell(command, confirm)
        except Exception as exc:  # noqa: BLE001
            return error_result(
                "run_shell", _host_of(controller), payload_from_error(exc), _elapsed_ms(started)
            )
        return ShellResult(
            ok=True,
            tool="run_shell",
            host=_host_of(controller),
            duration_ms=_elapsed_ms(started),
            data=ShellData(**data),
        )

    return mcp


async def _run_action(
    config: SSHConfig | None,
    name: str,
    action: Any,
    confirm: str | None,
) -> ServiceActionResult | ErrorResult:
    """写入类工具共用实现：安全校验 -> 二次确认 -> 执行 -> 结构化返回。"""
    started = time.perf_counter()
    controller = get_controller(config)
    tool_name = f"service_{action}"
    try:
        data = await controller.perform_action(name, action, confirm)
    except Exception as exc:  # noqa: BLE001
        return error_result(tool_name, _host_of(controller), payload_from_error(exc), _elapsed_ms(started))
    return ServiceActionResult(
        ok=True,
        tool=tool_name,
        host=_host_of(controller),
        duration_ms=_elapsed_ms(started),
        data=ServiceActionData(**data),
    )


def main(argv: list[str] | None = None) -> int:
    """命令行入口。"""
    import argparse

    parser = argparse.ArgumentParser(
        prog="router-ssh-mcp",
        description="通过 SSH 管理路由器服务的 MCP 服务器",
    )
    parser.add_argument("--config", help="JSON 配置文件路径（默认读取 ROUTER_MCP_CONFIG 或标准位置）")
    parser.add_argument("--host", help="覆盖 SSH 主机（等同 ROUTER_MCP_HOST）")
    parser.add_argument("--port", type=int, help="覆盖 SSH 端口")
    parser.add_argument("--user", help="覆盖 SSH 用户名")
    parser.add_argument("--password", help="覆盖 SSH 密码（不建议在命令行中使用）")
    parser.add_argument("--key-path", help="覆盖私钥路径")
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default="stdio",
        help="MCP 传输方式，默认 stdio（供桌面客户端拉起）",
    )
    parser.add_argument(
        "--allow-shell",
        action="store_true",
        help="启用高危的 shell 能力（默认关闭；等价于 ROUTER_MCP_ALLOW_SHELL=true）",
    )
    args = parser.parse_args(argv)

    import os

    # 命令行参数优先级最高：写入环境变量后统一由 load_config 处理
    overrides = {
        "ROUTER_MCP_HOST": args.host,
        "ROUTER_MCP_PORT": str(args.port) if args.port else None,
        "ROUTER_MCP_USER": args.user,
        "ROUTER_MCP_PASSWORD": args.password,
        "ROUTER_MCP_KEY_PATH": args.key_path,
        "ROUTER_MCP_CONFIG": args.config,
        "ROUTER_MCP_ALLOW_SHELL": "true" if args.allow_shell else None,
    }
    for key, value in overrides.items():
        if value:
            os.environ[key] = value

    server = create_server()
    server.run(transport=args.transport)
    return 0
