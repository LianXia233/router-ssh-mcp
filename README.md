# router-ssh-mcp

通过 SSH 管理路由器（OpenWrt / ImmortalWrt / 通用 Linux）上服务的 **MCP（Model Context Protocol）服务器**。
上层模型可以列出服务、查询状态、读取日志，并在二次确认后执行启动 / 停止 / 重启，全程受命令白名单约束；此外提供一个**默认关闭**的高危 `run_shell` 能力，在显式开启并二次确认后可于远端执行任意 shell 命令，用于白名单工具覆盖不到的排障场景。

---

## 1. 能力概览

| 能力 | 说明 |
| --- | --- |
| 多 init 系统 | 自动探测 `procd`（OpenWrt）、`systemd`、`sysvinit`，也可手动指定 |
| 连接复用 | 进程内复用单条 SSH 连接，带 keepalive 与断线重连 |
| 只读 / 写入分离 | 4 个只读工具 + 3 个写入工具，通过 MCP annotations 标注 |
| 写入二次确认 | 写入工具必须传 `confirm=<服务名>`，否则返回 `CONFIRMATION_REQUIRED` |
| 命令白名单 | 所有命令以 argv 序列下发，不经 shell；服务名、路径、行数均做严格校验 |
| 可选 shell 能力 | `run_shell` 默认关闭；开启后需二次确认，并默认拦截 rm -rf / mkfs / dd 等高危命令 |
| 结构化输出 | 统一返回 `ok/tool/host/duration_ms/data/error`，并附带 MCP structuredContent |
| 结构化错误 | 连接、认证、超时、服务不存在等均映射为稳定错误码 + 修复建议 |

---

## 2. 目录结构

```
router-ssh-mcp/
├── pyproject.toml               # 依赖与 console script 入口
├── config.example.json          # 配置文件示例（不含真实口令）
├── .env.example                 # 环境变量示例
├── src/router_mcp/
│   ├── config.py                # 配置加载（默认值 < 配置文件 < 环境变量）
│   ├── errors.py                # 错误码与结构化异常
│   ├── commands.py              # 命令白名单与 argv 模板（安全核心）
│   ├── ssh_pool.py              # SSH 连接复用 / 保活 / 超时重连 / 错误归类
│   ├── controller.py            # 编排层：安全策略、二次确认、工具语义
│   ├── models.py                # pydantic 返回模型
│   ├── server.py                # MCP 服务器与工具注册
│   ├── _compat.py               # mcp 1.x / 2.x 兼容层
│   └── backends/
│       ├── base.py              # 后端抽象与公共能力（启动时间推算）
│       ├── initd.py             # /etc/init.d 通用实现（sysvinit）
│       ├── procd.py             # OpenWrt ubus + procd
│       └── systemd.py           # systemctl + journalctl
├── scripts/
│   ├── selftest.py              # 真实设备自测（只读 + 可选写入演练）
│   └── mcp_smoke.py             # stdio 协议级冒烟测试
└── tests/                       # 离线单元测试 + MCP 层端到端测试
```

调用链：`MCP 工具 → controller（安全策略/确认） → backends（init 适配） → commands（白名单 argv） → ssh_pool（连接复用） → asyncssh`。

---

## 3. 环境要求与依赖

| 项目 | 要求 |
| --- | --- |
| Python | >= 3.10（CI 验证 3.11 / 3.12 / 3.13） |
| mcp | >= 2.0, < 3（SDK，代码内含 1.x 兼容路径） |
| asyncssh | >= 2.14（纯 Python SSH，自带 crypto，不需要系统 ssh 客户端） |
| pydantic | >= 2.7（结构化输出模型） |

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .          # 开发模式
# 或：pip install .
```

### Windows（PowerShell 7）

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

开发额外依赖：`pip install -e ".[dev]"`（pytest、pytest-asyncio）。

---

## 4. 配置

优先级：**默认值 < JSON 配置文件 < 环境变量 < 命令行参数**。

> **连接参数完全可自定义**：目标路由器 IP、登录账号、密码或私钥均由你按实际设备填写，三种方式任意组合。本仓库所有示例中的 `192.168.1.1` 仅为占位默认地址，请替换为你自己的路由器地址。密码与令牌**切勿提交进仓库**（`config.json` / `.env` 已在 `.gitignore` 中忽略）。

配置文件查找顺序：`--config` → `$ROUTER_MCP_CONFIG` → `./router-mcp.json` → `./config.json` → `~/.config/router-mcp/config.json`。

### 4.1 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ROUTER_MCP_HOST` | `192.168.1.1` | SSH 主机 |
| `ROUTER_MCP_PORT` | `22` | SSH 端口 |
| `ROUTER_MCP_USER` | `root` | SSH 用户名 |
| `ROUTER_MCP_PASSWORD` | — | 密码（与 `KEY_PATH` 至少提供一个） |
| `ROUTER_MCP_KEY_PATH` | — | 私钥路径 |
| `ROUTER_MCP_KEY_PASSPHRASE` | — | 私钥口令；未设置时会尝试用 `PASSWORD` 解密私钥 |
| `ROUTER_MCP_INIT_SYSTEM` | `auto` | `auto` / `procd` / `systemd` / `sysvinit` |
| `ROUTER_MCP_CONNECT_TIMEOUT` | `8` | 连接超时（秒） |
| `ROUTER_MCP_COMMAND_TIMEOUT` | `12` | 单条命令超时（秒） |
| `ROUTER_MCP_KEEPALIVE_INTERVAL` | `15` | 保活间隔（秒） |
| `ROUTER_MCP_KEEPALIVE_COUNT` | `3` | 连续保活失败次数阈值 |
| `ROUTER_MCP_MAX_RECONNECT_ATTEMPTS` | `2` | 命令失败重连重试次数 |
| `ROUTER_MCP_MAX_LOG_LINES` | `500` | 单次日志读取上限 |
| `ROUTER_MCP_REQUIRE_CONFIRM` | `true` | 写入操作是否要求二次确认 |
| `ROUTER_MCP_ALLOWED_SERVICES` | 空 | 服务白名单，逗号分隔；为空表示不限制 |
| `ROUTER_MCP_DENIED_SERVICES` | `network,firewall,system,boot,done` | 禁止写入的高危服务 |
| `ROUTER_MCP_STRICT_HOST_KEY` | `false` | 是否校验 known_hosts（路由器重装后建议临时关闭） |
| `ROUTER_MCP_KNOWN_HOSTS` | — | known_hosts 路径（仅在严格模式下生效） |
| `ROUTER_MCP_ALLOW_SHELL` | `false` | 是否启用高危的 `run_shell` 任意命令能力 |
| `ROUTER_MCP_SHELL_REQUIRE_CONFIRM` | `true` | `run_shell` 是否要求二次确认（confirm 须等于命令本身） |
| `ROUTER_MCP_SHELL_DENY_UNSAFE` | `true` | 是否拦截高危命令（rm -rf / mkfs / dd / 写 /dev/* / fork 炸弹 / 管道进 shell） |
| `ROUTER_MCP_LOG_LEVEL` | `WARNING` | asyncssh 日志级别，排障时设 `DEBUG` |

### 4.2 配置文件

复制 `config.example.json` 为 `config.json`（已在 `.gitignore` 中忽略，避免口令入库）：

```json
{
  "host": "192.168.1.1",
  "username": "root",
  "password": "",
  "init_system": "auto",
  "security": {
    "require_confirmation": true,
    "allowed_services": [],
    "denied_services": ["network", "firewall"]
  }
}
```

---

## 5. 启动

### 5.1 直接运行

```bash
# stdio（默认，供 MCP 客户端拉起）
ROUTER_MCP_HOST=192.168.1.1 ROUTER_MCP_PASSWORD=xxx python -m router_mcp

# 等价的 console script
ROUTER_MCP_HOST=192.168.1.1 ROUTER_MCP_PASSWORD=xxx router-ssh-mcp

# 命令行覆盖参数
router-ssh-mcp --host 192.168.1.1 --user root --key-path ~/.ssh/id_ed25519

# SSE / Streamable HTTP（远程部署时使用）
router-ssh-mcp --transport streamable-http
```

### 5.2 接入 MCP 客户端

WorkBuddy（`~/.workbuddy/mcp.json`）：

```json
{
  "mcpServers": {
    "router-ssh": {
      "description": "通过 SSH 管理路由器（OpenWrt/ImmortalWrt/systemd）服务的 MCP 连接器；只读工具可直接调用，写入操作需二次确认，run_shell 高危能力默认关闭。",
      "command": "python",
      "args": ["-m", "router_mcp"],
      "env": {
        "ROUTER_MCP_HOST": "192.168.1.1",
        "ROUTER_MCP_USER": "root",
        "ROUTER_MCP_PASSWORD": "你的密码"
      }
    }
  }
}
```

> 新增服务器后需在 WorkBuddy 的连接器管理页点击「信任」才会启用。

Claude Desktop / 其他支持 MCP 的客户端：`claude_desktop_config.json` 使用同样的 `mcpServers` 结构。

---

## 6. 工具清单

| 工具 | 类型 | 参数 | 说明 |
| --- | --- | --- | --- |
| `router_info` | 只读 | — | 连接健康、init 系统、设备信息、生效的安全策略 |
| `service_list` | 只读 | `name_filter?`, `running_only?`, `with_start_time?` | 列出服务及运行状态 |
| `service_status` | 只读 | `name` | 单服务详情（PID、启动时间、自启状态） |
| `service_logs` | 只读 | `name`, `lines=50` | 日志尾部（logread / journalctl） |
| `service_start` | 写入 | `name`, `confirm?` | 启动服务 |
| `service_stop` | 写入 | `name`, `confirm?` | 停止服务 |
| `service_restart` | 写入 | `name`, `confirm?` | 重启服务（非幂等） |
| `run_shell` | 高危 | `command`, `confirm?` | 在路由器上执行任意 shell 命令（默认关闭，需二次确认） |

### 6.1 成功返回示例

```json
{
  "ok": true,
  "tool": "service_status",
  "host": "192.168.1.1",
  "duration_ms": 412,
  "data": {
    "service": {
      "name": "dnsmasq",
      "running": true,
      "enabled": true,
      "pid": 2814,
      "started_at": "2026-09-10 09:00:12",
      "description": "/usr/sbin/dnsmasq -C /var/etc/dnsmasq.conf",
      "source": "procd"
    },
    "checked_at": "2026-09-10T09:21:03+08:00"
  },
  "error": null
}
```

### 6.2 需要二次确认时

```json
{
  "ok": false,
  "tool": "service_restart",
  "host": "192.168.1.1",
  "error": {
    "code": "CONFIRMATION_REQUIRED",
    "message": "写入操作 restart 需要二次确认",
    "hint": "确认无误后再次调用，并传入 confirm=\"dnsmasq\"",
    "details": {"service": "dnsmasq", "expected_confirm": "dnsmasq"}
  }
}
```

---

## 7. 安全模型

1. **无 shell 拼接**：所有命令以 argv 列表经 exec 通道下发，全程不出现 `sh -c`。
2. **服务名白名单**：`^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,63}$`，拒绝 `/`、空格、`;`、`|`、`&`、`$`、反引号、换行与 `..`。
3. **路径白名单**：可读路径限定为 `/proc/1/comm`、`/proc/uptime`、`/proc/stat`、`/etc/os-release`、`/etc/openwrt_release`、`/etc/init.d`、`/etc/rc.d`、`/run/systemd/system`。
4. **写入二次确认**：`confirm` 必须与目标服务名完全一致；可用 `ROUTER_MCP_REQUIRE_CONFIRM=false` 关闭（不推荐）。
5. **高危服务拒绝写入**：`network`、`firewall`、`system`、`boot`、`done` 默认只可读不可写（重启这些服务会断网或重启设备）。
6. **可选服务白名单**：设置 `ROUTER_MCP_ALLOWED_SERVICES` 后，白名单外的服务读写均被拒绝。
7. **只读 / 写入标注**：工具 annotations 标注 `readOnlyHint` / `destructiveHint` / `idempotentHint`，客户端可据此做权限提示。
8. **可选 shell 能力（高危，默认关闭）**：`run_shell` 必须显式设置 `ROUTER_MCP_ALLOW_SHELL=true` 才会出现并可调用；启用后命令仍经 `validate_shell_command` 校验，默认拦截 `rm -rf / mkfs / dd if= / 写入 /dev/* / fork 炸弹 / 管道进 shell` 等高危模式，且必须把 `confirm` 设为**命令本身的完整字符串**才会真正执行。shell 命令以 root 身份在远端登录 shell 中执行，绕过服务白名单——这是刻意保留的逃生通道，而非默认能力。
9. **口令不外泄**：`config.redacted()` 用于输出快照，日志与工具返回值中不含密码。

---

## 8. 错误码

| 错误码 | 触发场景 | 典型修复 |
| --- | --- | --- |
| `CONFIG_ERROR` | 缺少 host / 认证方式，配置文件非法 | 设置 `ROUTER_MCP_HOST` 与口令或私钥 |
| `INVALID_INPUT` | 服务名 / 行数 / 参数非法 | 使用 `service_list` 获取合法服务名 |
| `BLOCKED_COMMAND` | 路径或参数绕过白名单 | 属于实现缺陷，请提交 issue |
| `CONNECTION_FAILED` | TCP 不可达、连接被重置 | 检查 host/port、设备 SSH 服务与防火墙 |
| `AUTH_FAILED` | 用户名 / 密码 / 私钥错误 | 核对凭据；OpenWrt 默认用户为 `root` |
| `HOST_KEY_UNVERIFIED` | known_hosts 不匹配 | 更新 known_hosts 或临时关闭严格校验 |
| `COMMAND_TIMEOUT` | 命令超过 `COMMAND_TIMEOUT` | 调大超时，或检查设备负载 |
| `COMMAND_FAILED` | 命令返回非零退出码 | 查看返回中的 `stderr` 字段 |
| `SERVICE_NOT_FOUND` | 服务不存在 | 用 `service_list` 确认名称（注意大小写） |
| `PERMISSION_DENIED` | 命中黑名单 / 白名单外 / polkit 拒绝 | 调整安全策略或以 root 连接 |
| `CONFIRMATION_REQUIRED` | 写入操作缺少正确 confirm | 传入 `confirm="<服务名>"`；shell 则需 `confirm="<命令本身>"` |
| `SHELL_DISABLED` | 未开启 shell 能力却调用 `run_shell` | 设置 `ROUTER_MCP_ALLOW_SHELL=true` 启用（谨慎） |
| `UNSUPPORTED_ACTION` | 日志通道不可用（无 logread / journald） | 启用 logd 或 journald 持久化 |
| `BACKEND_ERROR` | 解析 ubus / systemctl 输出失败 | 检查系统版本兼容性 |

---

## 9. 本地自测步骤

共四层，从无依赖到真实设备逐级验证。

### 第 1 层：离线单元测试（无需设备、无需网络）

```bash
pip install -e ".[dev]"
python -m pytest -q
```

覆盖：命令白名单、配置优先级、procd/systemd 解析、确认机制、黑名单、超时映射、错误结构。

### 第 2 层：MCP 协议冒烟（验证客户端视角）

```bash
# 仅握手 + 列工具，不需要设备
python scripts/mcp_smoke.py

# 真实调用一次只读工具
ROUTER_MCP_HOST=192.168.1.1 ROUTER_MCP_USER=root ROUTER_MCP_PASSWORD=xxx \
  python scripts/mcp_smoke.py --call router_info

# 带参数调用
python scripts/mcp_smoke.py --call service_status --args '{"name": "dnsmasq"}'
```

预期输出：握手成功、7 个工具、读写标注正确；调用失败时返回 `ok=false` 与错误码。

### 第 3 层：真实设备自测（只读）

```bash
ROUTER_MCP_HOST=192.168.1.1 ROUTER_MCP_USER=root ROUTER_MCP_PASSWORD=xxx \
  python scripts/selftest.py
```

依次验证：SSH 连接与 init 探测 → 服务列表 → 单服务状态 → 日志读取 → 错误路径（服务不存在）→ 写入二次确认拦截，并输出表格化结果。加 `--json` 可查看原始返回。

### 第 4 层：写入演练（谨慎）

```bash
python scripts/selftest.py --host 192.168.1.1 --password xxx \
  --service dnsmasq --do-write
```

会真正执行一次 `restart`。建议先挑选无状态影响的服务（如 `dnsmasq`、`odhcpd`），不要在远程办公时段对 `network` / `firewall` 演练。

### 排障小贴士

| 现象 | 处理 |
| --- | --- |
| `AUTH_FAILED` | OpenWrt 默认禁止空密码；确认 dropbear 允许该用户登录 |
| `COMMAND_TIMEOUT` 频繁 | 设备 CPU 繁忙或网络丢包，调大 `ROUTER_MCP_COMMAND_TIMEOUT` |
| `logread` 无输出 | 确认 `logd` 在运行：`service_status(name="log")` |
| systemd 主机 `PERMISSION_DENIED` | 以 root 连接，或配置 polkit / sudo 规则 |
| 想看 SSH 握手细节 | 设置 `ROUTER_MCP_LOG_LEVEL=DEBUG`（日志仅写 stderr，不影响 stdio 协议） |

---

## 10. 已知限制

- 单条 SSH 连接复用，写入操作串行执行；高并发场景建议为每个设备起独立进程。
- OpenWrt 的启动时间依赖 `/proc/<pid>/stat` 与 `/proc/stat` 的 `btime`，容器或受限命名空间内可能拿不到。
- `service_list` 默认不填充 `started_at`（避免对每个服务额外发起命令），需要时传 `with_start_time=true` 或调用 `service_status`。
- systemd 主机上 `enabled` 判定包含 `static` 状态（视为自启）。
- 默认 `run_shell` 不可用（刻意的安全设计）；仅当用户显式设置 `ROUTER_MCP_ALLOW_SHELL=true` 后才提供任意命令执行能力。该通道仍受高危拦截列表与强制二次确认约束，但本质上以 root 身份运行，请仅在可信网络内启用。

---

## 11. 许可证

MIT
