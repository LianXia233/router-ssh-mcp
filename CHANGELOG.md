# 变更日志 / Changelog

本文件遵循 [语义化版本](https://semver.org/lang/zh-CN/) 约定。

## [0.2.0] - 2026-09-10

### 新增

- **高危 `run_shell` 能力**：在白名单服务管理之外，提供一个默认关闭的任意命令执行通道。
  - 通过 `ROUTER_MCP_ALLOW_SHELL=true`（或 `security.allow_shell` / `--allow-shell`）显式开启；未开启时调用返回 `SHELL_DISABLED`。
  - 命令经 `validate_shell_command` 校验：非空、长度上限 4000、无 NUL 与非常规控制字符。
  - 默认启用高危拦截列表（`ROUTER_MCP_SHELL_DENY_UNSAFE=true`），命中 `rm -rf` / `mkfs` / `dd if=` / 写入 `/dev/*` / fork 炸弹 / 管道进 shell 等模式的命令会被 `BLOCKED_COMMAND` 拒绝。
  - 强制二次确认：默认 `ROUTER_MCP_SHELL_REQUIRE_CONFIRM=true`，调用时必须把 `confirm` 设为命令本身的完整字符串，否则返回 `CONFIRMATION_REQUIRED`。
  - 命令以 root 身份在远端登录 shell 执行，绕过服务白名单；每次执行写入审计日志（仅含命令本身，不含任何凭据）。
- 配套单元测试与 MCP 协议层端到端测试（共 57 项，全部通过）。

### 安全

- `run_shell` 默认 `disabled`，不构成默认暴露面；其开关、确认与拦截均可独立配置，形成「显式开启 + 高危拦截 + 强制确认」三层护栏。

### 文档

- README 新增 shell 能力的配置项、工具说明、安全模型与错误码条目；`.env.example` 与 `config.example.json` 补充对应字段。

## [0.1.0] - 2026-09-09

### 新增

- 基于 MCP（Model Context Protocol）的 SSH 路由器服务管理服务器。
- 多 init 系统探测：procd（OpenWrt/ImmortalWrt）、systemd、sysvinit，亦可手动指定。
- 单条 SSH 连接复用、keepalive 保活、超时自动重连。
- 7 个工具：只读 `router_info` / `service_list` / `service_status` / `service_logs`，写入 `service_start` / `service_stop` / `service_restart`（需二次确认）。
- 命令白名单核心：所有命令以 argv 序列经 exec 通道下发，服务名 / 路径 / 行数严格校验，不经 shell 拼接。
- 结构化输出（统一 `ok/tool/host/duration_ms/data/error`）与结构化错误（稳定错误码 + 修复建议）。
- 启动入口、依赖说明、四层本地自测步骤（离线单测 / MCP 冒烟 / 真机只读 / 写入演练）。
