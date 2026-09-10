#!/usr/bin/env python3
"""真实设备自测脚本：验证 SSH 连接与只读工具链，可选验证写入确认机制。

用法（Linux/macOS/Windows 通用）：

    # 1) 纯只读自测（推荐首次验证）
    ROUTER_MCP_HOST=192.168.1.1 ROUTER_MCP_USER=root ROUTER_MCP_PASSWORD=<密码> \
        python scripts/selftest.py

    # 2) 指定服务 + 输出原始 JSON
    python scripts/selftest.py --host 192.168.1.1 --user root --password <密码> \
        --service dnsmasq --json

    # 3) 额外演练写入流程（仍不会真的重启：先验证缺 confirm 被拒，
    #    只有显式传入 --do-write 才会真正执行 restart）
    python scripts/selftest.py --host 192.168.1.1 --password <密码> --do-write \
        --service dnsmasq
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from router_mcp.config import load_config  # noqa: E402
from router_mcp.controller import RouterController  # noqa: E402
from router_mcp.errors import ToolError  # noqa: E402
from router_mcp.models import payload_from_error  # noqa: E402

STEP_OK = "PASS"
STEP_FAIL = "FAIL"
STEP_SKIP = "SKIP"


def _print_table(title: str, rows: list[list[str]], headers: list[str]) -> None:
    print(f"\n{title}")
    widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(str(cell)))
    line = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    print(line)
    print("| " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)) + " |")
    print(line)
    for row in rows:
        print("| " + " | ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)) + " |")
    print(line)


def _report(step: str, status: str, detail: str, results: list[list[str]]) -> None:
    results.append([step, status, detail])
    print(f"[{status}] {step}: {detail}")


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="router-ssh-mcp 本地自测")
    parser.add_argument("--host", help="SSH 主机（等同 ROUTER_MCP_HOST）")
    parser.add_argument("--port", type=int, help="SSH 端口")
    parser.add_argument("--user", help="SSH 用户名")
    parser.add_argument("--password", help="SSH 密码")
    parser.add_argument("--key-path", help="私钥路径")
    parser.add_argument("--config", help="JSON 配置文件路径")
    parser.add_argument("--service", help="用于状态/日志/写入演练的服务名（默认取第一个运行中的服务）")
    parser.add_argument("--do-write", action="store_true", help="真正执行 restart（需谨慎）")
    parser.add_argument(
        "--allow-shell",
        action="store_true",
        help="演练高危 run_shell 能力（同时会设 ROUTER_MCP_ALLOW_SHELL=true）",
    )
    parser.add_argument("--json", action="store_true", help="额外输出原始 JSON 结果")
    args = parser.parse_args(argv)

    for key, value in {
        "ROUTER_MCP_HOST": args.host,
        "ROUTER_MCP_PORT": str(args.port) if args.port else None,
        "ROUTER_MCP_USER": args.user,
        "ROUTER_MCP_PASSWORD": args.password,
        "ROUTER_MCP_KEY_PATH": args.key_path,
        "ROUTER_MCP_CONFIG": args.config,
        "ROUTER_MCP_ALLOW_SHELL": "true" if args.allow_shell else None,
    }.items():
        if value:
            os.environ[key] = value

    results: list[list[str]] = []
    payloads: dict[str, Any] = {}
    failures = 0

    try:
        config = load_config()
    except ToolError as exc:
        print(f"[{STEP_FAIL}] 配置加载: {exc}")
        return 2

    print(f"目标设备: {config.target}  认证方式: {'key' if config.key_path else 'password'}")
    controller = RouterController(config)

    # ---------------------------------------------------------------- 步骤 1：连接
    started = time.perf_counter()
    try:
        info = await controller.info()
        elapsed = int((time.perf_counter() - started) * 1000)
        backend = info["backend"]
        ssh = info["ssh"]
        payloads["router_info"] = info
        _report(
            "1. SSH 连接与探测",
            STEP_OK,
            f"init={backend} 复用={ssh.get('reuse_count')} 重连={ssh.get('reconnect_count')} "
            f"耗时={elapsed}ms server={ssh.get('server_version') or 'n/a'}",
            results,
        )
    except Exception as exc:  # noqa: BLE001
        payload = payload_from_error(exc).model_dump()
        _report("1. SSH 连接与探测", STEP_FAIL, f"{payload['code']} - {payload['message']}", results)
        print(f"    修复建议: {payload.get('hint')}")
        _print_table("自测结果", results, ["步骤", "状态", "说明"])
        return 1

    # ---------------------------------------------------------------- 步骤 2：服务列表
    try:
        services, init_system, _ = await controller.list_services()
        payloads["service_list"] = services
        _report("2. 服务列表", STEP_OK, f"共 {len(services)} 个服务（init={init_system}）", results)
        _print_table(
            "服务清单（前 15 条）",
            [
                [
                    item["name"],
                    "running" if item["running"] else ("stopped" if item["running"] is False else "unknown"),
                    "yes" if item["enabled"] else "no",
                    item["pid"] or "-",
                    item["source"],
                ]
                for item in services[:15]
            ],
            ["服务", "状态", "自启", "PID", "来源"],
        )
    except Exception as exc:  # noqa: BLE001
        payload = payload_from_error(exc).model_dump()
        failures += 1
        _report("2. 服务列表", STEP_FAIL, f"{payload['code']} - {payload['message']}", results)
        services = []

    # ---------------------------------------------------------------- 步骤 3：单个服务状态
    target = args.service
    if not target:
        target = next((item["name"] for item in services if item["running"]), None)
    if not target and services:
        target = services[0]["name"]

    if not target:
        _report("3. 服务状态", STEP_SKIP, "未发现可用服务", results)
    else:
        try:
            status = await controller.status(target)
            entry = status["service"]
            payloads["service_status"] = status
            _report(
                "3. 服务状态",
                STEP_OK,
                f"{entry['name']} running={entry['running']} pid={entry['pid']} "
                f"enabled={entry['enabled']} started_at={entry['started_at']}",
                results,
            )
        except Exception as exc:  # noqa: BLE001
            payload = payload_from_error(exc).model_dump()
            failures += 1
            _report("3. 服务状态", STEP_FAIL, f"{payload['code']} - {payload['message']}", results)

    # ---------------------------------------------------------------- 步骤 4：日志
    if target:
        try:
            logs = await controller.logs(target, 20)
            payloads["service_logs"] = logs
            _report(
                "4. 服务日志",
                STEP_OK,
                f"来源={logs['source']} 返回 {logs['returned_lines']}/{logs['requested_lines']} 行",
                results,
            )
            for line in logs["lines"][:5]:
                print(f"    | {line}")
        except Exception as exc:  # noqa: BLE001
            payload = payload_from_error(exc).model_dump()
            failures += 1  # 日志不可用不算致命，但记录下来
            _report("4. 服务日志", STEP_FAIL, f"{payload['code']} - {payload['message']}", results)

    # ---------------------------------------------------------------- 步骤 5：错误路径
    try:
        await controller.status("definitely-not-exist")
        _report("5. 错误路径（服务不存在）", STEP_FAIL, "未返回预期错误", results)
        failures += 1
    except ToolError as exc:
        expected = exc.code is not None and exc.code.value == "SERVICE_NOT_FOUND"
        _report(
            "5. 错误路径（服务不存在）",
            STEP_OK if expected else STEP_FAIL,
            f"返回 {exc.code.value}: {exc.message}",
            results,
        )
        failures += 0 if expected else 1

    # ---------------------------------------------------------------- 步骤 6：写入确认
    if target:
        try:
            await controller.perform_action(target, "restart", confirm=None)
            _report("6. 写入二次确认", STEP_FAIL, "缺少 confirm 却执行了写操作", results)
            failures += 1
        except ToolError as exc:
            ok = exc.code.value == "CONFIRMATION_REQUIRED"
            _report(
                "6. 写入二次确认",
                STEP_OK if ok else STEP_FAIL,
                f"缺 confirm 被拦截（{exc.code.value}）",
                results,
            )
            failures += 0 if ok else 1

        if args.do_write:
            try:
                result = await controller.perform_action(target, "restart", confirm=target)
                payloads["service_restart"] = result
                _report(
                    "7. 真实 restart 演练",
                    STEP_OK,
                    f"exit={result['exit_status']} "
                    f"before={result['state_before'] and result['state_before']['running']} "
                    f"after={result['state_after'] and result['state_after']['running']}",
                    results,
                )
            except ToolError as exc:
                failures += 1
                _report("7. 真实 restart 演练", STEP_FAIL, f"{exc.code.value} - {exc.message}", results)
        else:
            _report("7. 真实 restart 演练", STEP_SKIP, "未传 --do-write，跳过实际写入", results)

    # ---------------------------------------------------------------- 步骤 8：shell 能力（可选）
    if args.allow_shell:
        try:
            probe = "echo router-mcp-shell-ok"
            result = await controller.run_shell(probe, confirm=probe)
            payloads["run_shell"] = result
            ok = result["exit_status"] == 0 and "router-mcp-shell-ok" in result["stdout"]
            _report(
                "8. shell 能力演练",
                STEP_OK if ok else STEP_FAIL,
                f"exit={result['exit_status']} stdout={result['stdout'].strip()!r}",
                results,
            )
            failures += 0 if ok else 1
        except ToolError as exc:
            payload = payload_from_error(exc).model_dump()
            failures += 1
            _report("8. shell 能力演练", STEP_FAIL, f"{payload['code']} - {payload['message']}", results)
    else:
        _report("8. shell 能力演练", STEP_SKIP, "未传 --allow-shell，跳过高危通道", results)

    await controller.close()

    _print_table("自测结果", results, ["步骤", "状态", "说明"])
    if args.json:
        print("\n原始 JSON：")
        print(json.dumps(payloads, ensure_ascii=False, indent=2))

    if failures:
        print(f"\n存在 {failures} 项失败，请根据上面的错误码与 hint 排查。")
        return 1
    print("\n全部通过：SSH 连接、服务发现、状态查询、日志读取与错误处理均正常。")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
