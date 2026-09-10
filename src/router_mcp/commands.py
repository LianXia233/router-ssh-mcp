"""命令白名单与 argv 构建。

安全约束（硬性）：
    1. 所有命令以 **argv 序列**（list/tuple）形式下发，绝不经过远端 shell 解析；
       AsyncSSH 侧始终使用 exec 通道，不启用 ``shell=True``。
    2. 服务名、路径等外部输入必须匹配严格白名单正则，禁止包含 ``/``、空格、
       引号、``;``、``|``、``&``、``$``、反引号、换行等元字符。
    3. 可执行的程序名与路径来自本模块预置常量表，调用方无法注入任意命令。
    4. 每个命令都带 ``category`` 标记（read / write），写入类工具需二次确认。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Literal

from .errors import ErrorCode, ToolError

Category = Literal["read", "write"]

#: 服务（init 脚本 / systemd unit）名称白名单：
#: 允许字母数字开头，后续允许 . _ - + @；禁止路径穿越与 shell 元字符。
SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,63}$")

#: 允许读取的绝对路径（只读信息采集用）
ALLOWED_READ_PATHS: frozenset[str] = frozenset(
    {
        "/proc/1/comm",
        "/proc/uptime",
        "/proc/stat",
        "/etc/os-release",
        "/etc/openwrt_release",
        "/etc/init.d",
        "/etc/rc.d",
        "/run/systemd/system",
    }
)

#: 允许执行的程序；不同发行版/固件路径不一致，运行时按候选顺序探测
#: （见 router_mcp.programs.ProgramResolver，探测失败时回退首个候选）
PROGRAM_CANDIDATES: dict[str, tuple[str, ...]] = {
    "ubus": ("/sbin/ubus", "/bin/ubus", "/usr/sbin/ubus"),
    "logread": ("/sbin/logread", "/bin/logread", "/usr/sbin/logread"),
    "systemctl": ("/bin/systemctl", "/usr/bin/systemctl", "/usr/sbin/systemctl"),
    "journalctl": ("/bin/journalctl", "/usr/bin/journalctl"),
    "pidof": ("/bin/pidof", "/usr/bin/pidof"),
    "ls": ("/bin/ls", "/usr/bin/ls"),
    "cat": ("/bin/cat", "/usr/bin/cat"),
    "uname": ("/bin/uname", "/usr/bin/uname"),
    "tail": ("/usr/bin/tail", "/bin/tail"),
    "test": ("/bin/test", "/usr/bin/test"),
}

#: 命令模板中待解析的程序占位符（形如 {ubus}），执行前替换为真实路径
def program_token(key: str) -> str:
    if key not in PROGRAM_CANDIDATES:  # pragma: no cover - 实现缺陷保护
        raise ToolError(ErrorCode.BLOCKED_COMMAND, f"未登记的程序标识：{key}")
    return "{" + key + "}"


INIT_D_DIR = "/etc/init.d"

#: 审计用：模块内可产生的全部命令模板
COMMAND_CATALOG: tuple[str, ...] = (
    "init_d_action",
    "ubus_service_list",
    "systemctl_action",
    "systemctl_show",
    "systemctl_list_units",
    "systemctl_is_enabled",
    "journalctl_tail",
    "logread_tail",
    "pidof",
    "list_dir",
    "read_file",
    "uname",
    "probe_systemd",
)


@dataclass(frozen=True)
class CommandSpec:
    """一条待下发命令的完整描述。

    ``program`` 非空时，``argv[0]`` 是形如 ``{ubus}`` 的占位符，执行前由
    :class:`router_mcp.programs.ProgramResolver` 替换为探测到的真实路径。
    """

    template: str
    argv: tuple[str, ...]
    category: Category
    description: str
    program: str | None = None

    @property
    def display(self) -> str:
        return " ".join(self.argv)

    def with_program_path(self, path: str) -> "CommandSpec":
        """把占位符替换为真实路径，返回新的 CommandSpec。"""
        if not self.program:
            return self
        return replace(self, argv=(path, *self.argv[1:]))

    def to_dict(self) -> dict[str, object]:
        return {
            "template": self.template,
            "argv": list(self.argv),
            "category": self.category,
            "description": self.description,
            "display": self.display,
            "program": self.program,
        }


def validate_service_name(name: str) -> str:
    """校验服务名，返回规范化后的名称；非法时抛 INVALID_INPUT。"""
    if not isinstance(name, str) or not name.strip():
        raise ToolError(
            ErrorCode.INVALID_INPUT,
            "服务名不能为空",
            hint="传入 init 脚本名或 systemd unit 名，例如 dnsmasq / adguardhome / sshd.service",
        )
    candidate = name.strip()
    if not SERVICE_NAME_RE.match(candidate):
        raise ToolError(
            ErrorCode.INVALID_INPUT,
            f"服务名 {name!r} 不在白名单内（仅允许字母数字开头，可含 . _ - + @，最长 64 字符）",
            hint="检查是否误传了路径或 shell 片段，本服务不接受任意命令",
            details={"pattern": SERVICE_NAME_RE.pattern},
        )
    if ".." in candidate or candidate.startswith("."):
        raise ToolError(
            ErrorCode.INVALID_INPUT,
            f"服务名 {name!r} 含路径穿越片段",
            hint="只允许层级内的服务名，不允许 ./ ../ 等相对路径",
        )
    return candidate


def validate_lines(lines: int, max_lines: int) -> int:
    """校验日志行数。"""
    try:
        value = int(lines)
    except (TypeError, ValueError) as exc:
        raise ToolError(
            ErrorCode.INVALID_INPUT,
            f"日志行数不是整数：{lines!r}",
            hint="传入 1 ~ %d 之间的整数" % max_lines,
        ) from exc
    if value < 1:
        raise ToolError(
            ErrorCode.INVALID_INPUT,
            "日志行数必须大于 0",
            hint="例如 lines=50",
        )
    if value > max_lines:
        raise ToolError(
            ErrorCode.INVALID_INPUT,
            f"日志行数 {value} 超过上限 {max_lines}",
            hint="调小 lines，或提高 ROUTER_MCP_MAX_LOG_LINES",
        )
    return value


def validate_argument(value: str, field: str = "参数") -> str:
    """校验单个命令参数（不含空白与 shell 元字符）。"""
    if not isinstance(value, str):
        raise ToolError(ErrorCode.INVALID_INPUT, f"{field} 必须是字符串")
    if any(ch.isspace() for ch in value):
        raise ToolError(
            ErrorCode.INVALID_INPUT,
            f"{field} 不允许包含空白字符",
            hint="本服务以 argv 方式执行命令，不接受需要 shell 解析的片段",
        )
    if any(ch in value for ch in ";&|`$<>(){}[]*?!\"'\\\n\r\t"):
        raise ToolError(
            ErrorCode.INVALID_INPUT,
            f"{field} 含被禁止的 shell 元字符",
            hint="仅允许字母数字与 . _ - + @ / = : , 等安全字符",
        )
    return value


def _finalize(
    template: str,
    argv: list[str],
    category: Category,
    description: str,
    program: str | None = None,
) -> CommandSpec:
    for item in argv:
        if not isinstance(item, str) or not item:
            raise ToolError(
                ErrorCode.BLOCKED_COMMAND,
                f"命令 {template} 参数为空",
                hint="这是实现缺陷，请提交 issue",
            )
        if "\n" in item or "\r" in item or "\x00" in item:
            raise ToolError(
                ErrorCode.BLOCKED_COMMAND,
                f"命令 {template} 参数含控制字符，已拒绝执行",
                hint="参数必须来自白名单模板",
            )
    return CommandSpec(
        template=template,
        argv=tuple(argv),
        category=category,
        description=description,
        program=program,
    )


# --------------------------------------------------------------------------
# 命令模板
# --------------------------------------------------------------------------


def init_d_action(name: str, action: Literal["start", "stop", "restart", "reload", "status"]) -> CommandSpec:
    """/etc/init.d/<name> <action>，OpenWrt/procd 与 sysvinit 通用。"""
    service = validate_service_name(name)
    return _finalize(
        "init_d_action",
        [f"{INIT_D_DIR}/{service}", action],
        "read" if action == "status" else "write",
        f"对 {service} 执行 init 脚本动作 {action}",
    )


def ubus_service_list(name: str | None = None) -> CommandSpec:
    """列出 procd 服务（``ubus call service list``），可选按名称过滤。"""
    argv = [program_token("ubus"), "call", "service", "list"]
    if name:
        argv.append(f'{{"name": "{validate_service_name(name)}"}}')
    return _finalize(
        "ubus_service_list",
        argv,
        "read",
        "通过 ubus 列出 procd 服务与实例",
        program="ubus",
    )


def systemctl_action(name: str, action: Literal["start", "stop", "restart", "reload"]) -> CommandSpec:
    service = validate_service_name(name)
    return _finalize(
        "systemctl_action",
        [program_token("systemctl"), action, service],
        "write",
        f"systemctl {action} {service}",
        program="systemctl",
    )


def systemctl_show(name: str) -> CommandSpec:
    service = validate_service_name(name)
    return _finalize(
        "systemctl_show",
        [
            program_token("systemctl"),
            "show",
            service,
            "--no-pager",
            "--property=Id,LoadState,ActiveState,SubState,ExecMainPID,ExecMainStartTimestamp,"
            "UnitFileState,Description,FragmentPath,ActiveEnterTimestamp",
        ],
        "read",
        f"读取 {service} 的 systemd 属性",
        program="systemctl",
    )


def systemctl_list_units() -> CommandSpec:
    return _finalize(
        "systemctl_list_units",
        [
            program_token("systemctl"),
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--plain",
            "--no-pager",
            "--output=json",
        ],
        "read",
        "列出全部 systemd service unit",
        program="systemctl",
    )


def systemctl_is_enabled(name: str) -> CommandSpec:
    service = validate_service_name(name)
    return _finalize(
        "systemctl_is_enabled",
        [program_token("systemctl"), "is-enabled", service],
        "read",
        f"查询 {service} 是否开机自启",
        program="systemctl",
    )


def journalctl_tail(name: str, lines: int) -> CommandSpec:
    service = validate_service_name(name)
    return _finalize(
        "journalctl_tail",
        [
            program_token("journalctl"),
            "-u",
            service,
            "-n",
            str(int(lines)),
            "--no-pager",
            "-o",
            "short-iso",
        ],
        "read",
        f"读取 {service} 最近 {lines} 条 journal 日志",
        program="journalctl",
    )


def logread_tail(lines: int, pattern: str | None = None) -> CommandSpec:
    """OpenWrt ring buffer 日志；pattern 走 ``-e`` 参数（argv 形式，无 shell）。"""
    argv = [program_token("logread"), "-l", str(int(lines))]
    if pattern:
        argv += ["-e", validate_argument(pattern, "日志过滤关键字")]
    return _finalize(
        "logread_tail",
        argv,
        "read",
        f"读取系统日志尾部 {lines} 条",
        program="logread",
    )


def proc_pid_stat(pid: int) -> CommandSpec:
    """读取 /proc/<pid>/stat 用于计算进程启动时间（pid 必须是正整数）。"""
    try:
        pid_int = int(pid)
    except (TypeError, ValueError) as exc:
        raise ToolError(
            ErrorCode.INVALID_INPUT, f"PID 不是整数：{pid!r}", hint="PID 必须来自上一步查询结果"
        ) from exc
    if pid_int <= 0 or pid_int > 4_194_304:
        raise ToolError(ErrorCode.INVALID_INPUT, f"PID 超出合法范围：{pid}")
    return _finalize(
        "read_file",
        [program_token("cat"), f"/proc/{pid_int}/stat"],
        "read",
        f"读取 PID {pid_int} 的 stat",
        program="cat",
    )


def systemctl_list_unit_files() -> CommandSpec:
    return _finalize(
        "systemctl_list_units",
        [
            program_token("systemctl"),
            "list-unit-files",
            "--type=service",
            "--no-legend",
            "--plain",
            "--no-pager",
        ],
        "read",
        "列出 systemd unit 文件的开机自启状态",
        program="systemctl",
    )


def pidof(name: str) -> CommandSpec:
    service = validate_service_name(name)
    return _finalize(
        "pidof",
        [program_token("pidof"), service],
        "read",
        f"查询 {service} 进程 PID",
        program="pidof",
    )


def list_dir(path: str) -> CommandSpec:
    if path not in ALLOWED_READ_PATHS:
        raise ToolError(
            ErrorCode.BLOCKED_COMMAND,
            f"路径 {path!r} 不在允许列表内",
            hint=f"仅允许：{sorted(ALLOWED_READ_PATHS)}",
        )
    return _finalize(
        "list_dir",
        [program_token("ls"), "-1", path],
        "read",
        f"列目录 {path}",
        program="ls",
    )


def read_file(path: str) -> CommandSpec:
    if path not in ALLOWED_READ_PATHS:
        raise ToolError(
            ErrorCode.BLOCKED_COMMAND,
            f"路径 {path!r} 不在允许列表内",
            hint=f"仅允许：{sorted(ALLOWED_READ_PATHS)}",
        )
    return _finalize(
        "read_file",
        [program_token("cat"), path],
        "read",
        f"读取 {path}",
        program="cat",
    )


def uname() -> CommandSpec:
    return _finalize(
        "uname",
        [program_token("uname"), "-a"],
        "read",
        "读取内核与主机信息",
        program="uname",
    )


def probe_systemd() -> CommandSpec:
    """/run/systemd/system 存在即视为 systemd 主机（不依赖 which/command -v）。"""
    return _finalize(
        "probe_systemd",
        [program_token("test"), "-d", "/run/systemd/system"],
        "read",
        "探测主机是否为 systemd",
        program="test",
    )


def tail_file(path: str, lines: int) -> CommandSpec:
    """仅用于 sysvinit 场景读取 /var/log/<service>.log 等固定路径。"""
    safe_path = validate_argument(path, "日志文件路径")
    if not safe_path.startswith("/var/log/"):
        raise ToolError(
            ErrorCode.BLOCKED_COMMAND,
            f"日志路径 {path!r} 不在允许范围",
            hint="仅允许 /var/log/ 下的文件",
        )
    return _finalize(
        "journalctl_tail",
        [program_token("tail"), "-n", str(int(lines)), safe_path],
        "read",
        f"读取 {safe_path} 尾部 {lines} 行",
        program="tail",
    )


# --------------------------------------------------------------------------
# 任意 shell 命令（高危能力，默认关闭，仅当 security.allow_shell=true 才可用）
# --------------------------------------------------------------------------

#: 单条 shell 命令的最大长度（避免异常超长输入影响解析与审计）。
MAX_SHELL_LENGTH = 4000

#: 高危模式拦截列表（仅在 shell_deny_unsafe=true 时生效）。注意：这是**基础防护**
#: 而非沙箱——它只能拦住常见误用，无法阻止一个有心的用户通过编码/分号/引号绕过。
#: 真正的边界是 allow_shell 开关本身与二次确认。
SHELL_DENY_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\brm\s+(-[A-Za-z]+\s+)*(-r|-f|-rf|-fr|-force)\b", "递归/强制删除（rm -rf / -r / -f）"),
    (r"\bmkfs(\.\w+)?\b", "格式化文件系统（mkfs）"),
    (r"\bmkswap\b", "创建交换分区（mkswap）"),
    (r"\bdd\s+(if|of)=", "整盘/分区写入（dd if= / dd of=）"),
    (r">\s*/dev/[a-zA-Z]+\b", "写入块设备（> /dev/...）"),
    (r":\(\)\s*\{\s*:", "fork 炸弹（:(){:|:&}）"),
    (r"\|\s*(sh|bash|ash|busybox)\b", "管道进入 shell（curl/wget/echo ... | sh）"),
    (r"\b(curl|wget|fetch)\b[^|]*(>\s*/dev/)", "下载并写入设备（curl/wget ... > /dev/...）"),
)


def validate_shell_command(command: str, *, deny_unsafe: bool = True) -> str:
    """校验任意 shell 命令，返回规范化后的命令字符串。

    校验项（与白名单命令通道相互独立，这里是 shell 专属的弱化护栏）：

    * 非空且非纯空白；
    * 长度不超过 :data:`MAX_SHELL_LENGTH`；
    * 不含 NUL 与除 ``\\t \\n \\r`` 之外的控制字符；
    * 当 ``deny_unsafe`` 为真时，命中 :data:`SHELL_DENY_PATTERNS` 高危模式直接拒绝。

    注意：本函数并不阻止 shell 元字符（``;``, ``|``, ``&``, ``$`` 等），因为 shell
    能力的本质就是把这些交给远端 shell 解析——这由其默认关闭、需二次确认、需显式
    开启的设计来保证安全，而非靠字符过滤。
    """
    if not isinstance(command, str) or not command.strip():
        raise ToolError(
            ErrorCode.INVALID_INPUT,
            "shell 命令不能为空",
            hint="请传入希望在路由器上执行的命令字符串",
        )
    if "\x00" in command:
        raise ToolError(
            ErrorCode.BLOCKED_COMMAND,
            "shell 命令含 NUL 字符，已拒绝",
            hint="命令不得包含 \\x00",
        )
    if len(command) > MAX_SHELL_LENGTH:
        raise ToolError(
            ErrorCode.INVALID_INPUT,
            f"shell 命令超过长度上限 {MAX_SHELL_LENGTH} 字符",
            hint="拆分命令或缩短参数后重试",
            details={"max_length": MAX_SHELL_LENGTH},
        )
    for ch in command:
        code = ord(ch)
        if (code < 0x20 or code == 0x7F) and ch not in "\t\n\r":
            raise ToolError(
                ErrorCode.BLOCKED_COMMAND,
                f"shell 命令含控制字符 {ch!r}，已拒绝",
                hint="仅允许可见字符及制表/换行/回车",
            )
    if deny_unsafe:
        for pattern, reason in SHELL_DENY_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                raise ToolError(
                    ErrorCode.BLOCKED_COMMAND,
                    f"shell 命令命中高危拦截模式，已拒绝：{reason}",
                    hint=(
                        "该命令默认被高危拦截列表拦截；如确需执行，可设置 "
                        "ROUTER_MCP_SHELL_DENY_UNSAFE=false（仍须二次确认），"
                        "或改用非危险等价的服务管理工具"
                    ),
                    details={"matched": pattern, "reason": reason},
                )
    return command
