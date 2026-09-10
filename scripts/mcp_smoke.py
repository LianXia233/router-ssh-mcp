#!/usr/bin/env python3
"""MCP 协议级冒烟测试：以 stdio 客户端真实拉起服务器并调用工具。

这一步验证「客户端视角」的可用性：进程能否被拉起、协议握手是否正常、
工具清单与读写标注是否暴露、错误是否以结构化内容返回。

用法：

    # 仅握手 + 列工具（不需要设备）
    python scripts/mcp_smoke.py

    # 连真实设备做一次只读调用
    ROUTER_MCP_HOST=192.168.1.1 ROUTER_MCP_USER=root ROUTER_MCP_PASSWORD=<密码> \
        python scripts/mcp_smoke.py --call router_info

    # 调用带参数的工具
    python scripts/mcp_smoke.py --call service_status --args '{"name": "dnsmasq"}'
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _dump(result: Any) -> str:
    structured = getattr(result, "structuredContent", None) or getattr(
        result, "structured_content", None
    )
    if structured:
        return json.dumps(structured, ensure_ascii=False, indent=2)
    return "\n".join(getattr(item, "text", str(item)) for item in getattr(result, "content", []))


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MCP stdio 冒烟测试")
    parser.add_argument("--call", help="要调用的工具名（默认只列工具）")
    parser.add_argument("--args", default="{}", help="工具参数 JSON 字符串")
    parser.add_argument("--env", action="append", default=[], help="额外环境变量，形如 KEY=VALUE")
    args = parser.parse_args(argv)

    env = os.environ.copy()
    for item in args.env:
        key, _, value = item.partition("=")
        env[key] = value

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "router_mcp"],
        env=env,
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print(f"握手成功，共 {len(tools.tools)} 个工具：")
            for tool in tools.tools:
                hint = tool.annotations.read_only_hint if tool.annotations else None
                kind = "read " if hint else "write"
                print(f"  - {tool.name:<16} [{kind}]")

            if not args.call:
                print("\n未指定 --call，已完成握手与工具清单验证。")
                return 0

            call_args = json.loads(args.args)
            print(f"\n调用 {args.call}({call_args}) ...")
            result = await session.call_tool(args.call, call_args)
            print(_dump(result))
            return 1 if getattr(result, "isError", False) else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
