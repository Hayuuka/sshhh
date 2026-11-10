"""sshhh —— 让 AI agent 使用 SSH，而密码永远不进入它的上下文。

这是 agent 调用的唯一入口。典型调用：

    python sshhh.py run prod "df -h"

首次运行会自动拉起一个控制台窗口让用户设置主密码和服务器，
之后所有调用都复用同一份加密密码库（~/.sshhh/vault.enc）。
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from lib import paths  # noqa: E402
from lib.lock import LockTimeout  # noqa: E402

_SELF = Path(__file__).resolve()

USAGE = """\
sshhh —— AI 可用的 SSH 通道，密码不进入 AI 上下文

  run <主机> <命令...>     执行命令（退出码透传）
  list                    列出已配置的主机
  test <主机>              连通性测试
  put <主机> <本地> <远端>   上传文件
  get <主机> <远端> <本地>   下载文件
  status                  查看整体状态
  audit [-n N]            查看最近的调用记录

  config [--here]         打开配置窗口；加 --here 则在当前终端里配置
  setpass <主机>           修改某台主机的密码
  unlock                  重新输入主密码
  setup                   只安装运行环境
  migrate <旧目录>         从旧版 sshx 项目迁移主机和密码

数据目录（所有 agent 共用）：{data}
"""


# --------------------------------------------------------------------------
# 基础
# --------------------------------------------------------------------------


def _setup_io() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def _say(msg: str = "") -> None:
    print(msg)


def _warn(msg: str) -> None:
    print(msg, file=sys.stderr)


class UsageError(Exception):
    pass


# 可以写在位置参数之后的长选项（布尔型）。
# 短选项不在此列：远端命令里的 `-n` / `-f` 很常见，不能吞。
_LONG_BOOL_FLAGS = frozenset({"sudo"})


def _parse(argv: list[str], value_flags: set[str]) -> tuple[dict, list[str]]:
    """解析参数。

    长选项（`--timeout` / `--stdin-file` / `--sudo` / `--stdin`）写在主机名
    之前或之后都等价：

        run --sudo hk "systemctl restart nginx"
        run hk --sudo "systemctl restart nginx"

    短选项仍只识别第一个位置参数之前的，避免把远端命令里的 `-n` 当成本地选项。
    需要把 `--sudo` 这类字样原样交给远端时，用 `--` 显式分隔：

        run hk -- "--sudo something"
    """
    opts: dict = {}
    pos: list[str] = []
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            pos.extend(argv[i + 1:])
            break
        if token.startswith("--") and len(token) > 2:
            name, sep, inline = token[2:].partition("=")
            if name in value_flags:
                if sep:
                    opts[name] = inline
                else:
                    i += 1
                    if i >= len(argv):
                        raise UsageError(f"--{name} 需要一个值")
                    opts[name] = argv[i]
            elif name in _LONG_BOOL_FLAGS:
                if sep:
                    raise UsageError(f"--{name} 不接受值")
                opts[name] = True
            elif pos:
                # 位置参数之后的未知长选项属于远端命令，原样保留
                pos.append(token)
            elif sep:
                opts[name] = inline
            else:
                opts[name] = True
        elif token.startswith("-") and len(token) > 1 and not pos:
            flag = token[1:]
            if flag in value_flags:
                i += 1
                if i >= len(argv):
                    raise UsageError(f"-{flag} 需要一个值")
                opts[flag] = argv[i]
            else:
                for ch in flag:
                    opts[ch] = True
        else:
            pos.append(token)
        i += 1
    return opts, pos


def _manual_cmd(sub: str) -> str:
    # 这个环境里弹窗撑不住时，manual 的 config 自动变成 --here
    if sub == "config" and paths.no_window_marker().exists():
        sub = "config --here"
    return f'python "{_SELF}" {sub}'


def _python_too_old_hint() -> str:
    """当前 Python 低于 3.9 时给用户的指引。

    只覆盖「有 Python 但太旧」。如果机器上完全没有 Python，脚本根本启动不了，
    那种情况脚本没法自己报，必须由 agent 看到 command not found 后判断
    （见 SKILL.md 的「如果 python 命令本身不存在」一节）。
    """
    return (
        "这台机器上的 Python 版本低于 3.9，跑不了本脚本。请告诉用户：\n"
        "1. 打开 https://www.python.org/downloads/ 安装 Python 3.9 或更高版本\n"
        '   安装时勾选 "Add python.exe to PATH"\n'
        "2. 装完重新执行刚才的命令，不需要设置任何环境变量\n"
        "注意：机器上其实已经装了 Python，只是版本旧，说的是升级不是首次安装"
    )


def _deps_hint() -> str:
    """有 Python，但虚拟环境或依赖装不上。"""
    return (
        "运行环境没装好（依赖下载失败）。请告诉用户在自己的终端里执行：\n"
        f"{_manual_cmd('setup')}\n"
        "如果卡在下载，可以先换国内镜像源再执行：\n"
        "  set PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple"
    )


# --------------------------------------------------------------------------
# 配置窗口编排
# --------------------------------------------------------------------------


def _setup_timeout() -> float:
    """配置窗口等待时长。

    默认 180 秒，可用 SSHHH_SETUP_TIMEOUT 覆盖；合法范围 30-600，
    超出范围或非法值一律回落默认，避免把等待时间设成 0 或无穷大。
    """
    default = float(paths.DEFAULT_SETUP_TIMEOUT)
    raw = os.environ.get("SSHHH_SETUP_TIMEOUT")
    if raw is None:
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    if not (paths.MIN_SETUP_TIMEOUT <= value <= paths.MAX_SETUP_TIMEOUT):
        return default
    return value


def _unknown_host(name: str) -> int:
    """主机不存在时的统一出口。

    注意：这里返回 3（配置错误），不是 2（参数错误）——参数格式没问题，
    只是清单里没有这台机器。也不是 13（LOCKED），密码库此时是好的。
    """
    from lib import protocol

    _warn(f"[sshhh] 未知主机：{name}")
    _warn("[sshhh] 可用 list 查看已有主机，或用 run / config 触发添加")
    return protocol.EXIT_CONFIG


def _handoff_seconds() -> float | None:
    """等多久就把窗口交给用户。

    默认 120 秒 —— 设主密码（输两遍）+ 填主机信息，一两分钟很正常。

    窗口由 explorer 拉起，不在本进程的作业对象里，所以本进程退出（或被
    宿主杀掉）都不影响它。交接只是为了让 agent 早点拿到一个明确状态，
    而不是为了保住窗口。

    `SSHHH_SETUP_HANDOFF=0` 表示不交接，一直等到窗口结束或超时。
    """
    default = 120.0
    raw = os.environ.get("SSHHH_SETUP_HANDOFF")
    if raw is None:
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    if value <= 0:
        return None
    return min(value, 600.0)


def _launch(task: str, payload: dict) -> tuple[str, dict]:
    from lib import console

    if not console.available():
        return console.TIMEOUT, {}
    return console.launch(task, payload, _setup_timeout(), _handoff_seconds())


def _setup_failed(status: str, detail: dict, manual_sub: str) -> int:
    """把配置窗口的非成功结果翻译成协议状态码。"""
    from lib import protocol

    if status == "cancel":
        return protocol.emit(
            protocol.EXIT_CANCELLED, "用户取消了配置，未做任何修改"
        )
    if status == "timeout":
        return protocol.emit(
            protocol.EXIT_TIMEOUT,
            "配置窗口等待超时",
            hint=(
                "配置窗口等待超时。请告诉用户在自己的终端里执行：\n"
                f"{_manual_cmd(manual_sub)}\n"
                "窗口可能还开着，里面输入完会照样生效；如果已经关了，重跑上面这条"
            ),
        )
    if status == "gone":
        return protocol.emit(
            protocol.EXIT_TIMEOUT,
            "配置窗口被外部终止了，配置没有完成",
            hint=(
                "这个环境会在命令结束时把残留进程一起回收，弹窗撑不住。\n"
                "请告诉用户：在自己的终端里执行下面的命令，全程在当前终端完成，"
                "不会再弹新窗口：\n"
                f"{_manual_cmd('config --here')}"
            ),
        )
    if status == "pending":
        if detail.get("active"):
            return protocol.emit(
                protocol.EXIT_PENDING,
                "已经有一个配置窗口在等用户输入",
                hint=(
                    "用户正在窗口里填主密码和服务器信息，这需要一两分钟，属于正常。\n"
                    "不要重复调用本命令，也不要再开新窗口；等用户说填完了，"
                    "再重试原命令一次。\n"
                    "窗口标题是「sshhh setup」，如果用户说找不到，让他在任务栏里找一下。"
                ),
            )
        return protocol.emit(
            protocol.EXIT_PENDING,
            "配置窗口已打开，正在等待用户输入",
            hint=(
                "请告诉用户：桌面上已经打开了一个配置窗口，请在里面设置主密码、"
                "再填一台服务器的信息（地址、用户名、端口、密码），不用赶时间。\n"
                "窗口是独立进程，就算这里的命令被中断也不会关。用户填完后，"
                "再重试原命令即可。\n"
                "不要反复调用本命令，也不要再开新窗口。"
            ),
        )
    err = detail.get("error") or "配置窗口返回错误"
    return protocol.emit(
        protocol.EXIT_CONFIG, str(err),
        hint=("如果配置窗口反复异常退出，可以直接在用户自己的终端里执行下面的命令，"
              "全程不弹新窗口：\n"
              f"{_manual_cmd('config --here')}"),
    )


def _run_here(task: str, payload: dict) -> int:
    """在当前终端里直接跑配置向导（不弹窗）。"""
    from lib import protocol

    if not sys.stdin.isatty():
        return protocol.emit(
            protocol.EXIT_CONFIG,
            "当前终端不可交互，无法在这里配置",
            hint=("请在真实的终端窗口里执行：\n"
                  f"{_manual_cmd('config --here')}"),
        )

    import console_setup

    handler = console_setup.TASKS.get(task)
    if handler is None:
        return protocol.emit(protocol.EXIT_CONFIG, f"未知任务：{task}")

    try:
        result = handler(payload)
    except KeyboardInterrupt:
        print()
        return protocol.emit(protocol.EXIT_CANCELLED, "已取消，未做任何修改")
    except Exception as exc:  # noqa: BLE001
        return protocol.emit(
            protocol.EXIT_CONFIG, f"配置失败：{exc}",
            hint=f"详细日志见 {paths.data_dir() / 'console.log'}",
        )

    host = str(result.get("host") or "")
    _say(f"[ok] 配置完成{f'，主机 {host}' if host else ''}")
    return 0


# --------------------------------------------------------------------------
# 命令实现
# --------------------------------------------------------------------------


def cmd_setup(argv: list[str]) -> int:
    from lib import runtime

    _parse(argv, set())
    try:
        runtime.ensure()
    except runtime.PythonTooOldError as exc:
        _warn(f"[sshhh] {exc}")
        _warn("[sshhh] 请升级 Python 到 3.9+：https://www.python.org/downloads/")
        _warn('[sshhh] 安装时勾选 "Add python.exe to PATH"，装好后重新执行本命令')
        return 20
    except runtime.RuntimeError_ as exc:
        _warn(f"[sshhh] {exc}")
        _warn("[sshhh] 如果卡在下载，可换国内镜像后重试：")
        _warn("        set PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple")
        _warn(f"[sshhh] 然后重新执行：{_manual_cmd('setup')}")
        return 20
    _say("[ok] 运行环境已就绪")
    return 0


def _stdin_data(opts: dict) -> str | None:
    """取要喂给远端命令的标准输入。

    内容一律不经过 argv —— argv 会进进程列表，也会进审计（#29）：

        cat schema.sql | sshhh run prod --stdin - "mysql -u app"
        sshhh run prod --stdin-file ./schema.sql "mysql -u app"

    `--stdin` 只接受 `-`（标准输入）。旧写法 `--stdin <值>` 直接报错而不是
    默默忽略：那个值会变成命令的一部分，等于把秘密写进审计日志。
    """
    if "stdin" in opts:
        value = str(opts["stdin"])
        if value != "-":
            raise UsageError(
                "--stdin 只接受 -（表示从标准输入读取）。\n"
                "旧的 --stdin <值> 写法已删除：值会进 argv、进程列表和审计日志。\n"
                "请改用：cat 文件 | sshhh run <主机> --stdin - <命令>\n"
                "        或：sshhh run <主机> --stdin-file <文件> <命令>"
            )
        return sys.stdin.read() or None
    if "stdin-file" in opts:
        source = str(opts["stdin-file"])
        if source == "-":
            return sys.stdin.read() or None
        try:
            return Path(source).expanduser().read_text(encoding="utf-8") or None
        except OSError as exc:
            raise UsageError(f"读不了 --stdin-file {source}：{exc}") from None
    return None


def _int_opt(opts: dict, flag: str, default: int,
             allow_zero: bool) -> tuple[int, bool]:
    """读一个整数选项，返回 (值, 是否出现过)。"""
    if flag not in opts:
        return default, False
    raw = str(opts[flag])
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise UsageError(f"--{flag} 需要一个整数，收到 {raw!r}") from None
    if value < 0 or (value == 0 and not allow_zero):
        raise UsageError(
            f"--{flag} 需要{'非负整数（0 = 不限制）' if allow_zero else '正整数'}，"
            f"收到 {value}"
        )
    return value, True


def _float_opt(opts: dict, flag: str) -> float | None:
    if flag not in opts:
        return None
    raw = str(opts[flag])
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise UsageError(f"--{flag} 需要一个数字，收到 {raw!r}") from None
    if value <= 0:
        raise UsageError(f"--{flag} 需要正数，收到 {value}")
    return value


def _output_opts(opts: dict) -> tuple[int, int | None]:
    """解析 `--max-bytes` / `--tail`。

    默认 50 KiB 上限：够看一份日志尾巴、一份 `df -h`，又不至于把会话上下文
    灌满。`--max-bytes 0` 表示不限制，`--tail N` 只回传最后 N 行。
    """
    from lib import output

    max_bytes, _ = _int_opt(opts, "max-bytes", output.DEFAULT_MAX_BYTES,
                            allow_zero=True)
    tail_lines, present = _int_opt(opts, "tail", 0, allow_zero=False)
    return max_bytes, (tail_lines if present else None)


def cmd_run(argv: list[str]) -> int:
    from lib import audit, output, protocol, store, vault
    from lib.redact import Redactor
    from lib.transport import Client, TransportError

    opts, pos = _parse(argv, {"timeout", "stdin", "stdin-file",
                              "max-bytes", "tail"})
    if not pos:
        raise UsageError('用法：sshhh run <主机> "<命令>"')
    name = pos[0]
    command = " ".join(pos[1:]).strip()
    if not command:
        raise UsageError('缺少要执行的命令，例如：sshhh run prod "df -h"')

    # --- 1. 没有密码库：先配置 -------------------------------------------
    if not paths.vault_file().exists():
        status, detail = _launch("setup", {})
        if status != "ok":
            return _setup_failed(status, detail, "config")
        return protocol.emit(
            protocol.EXIT_CONFIGURED, "已经完成初始化配置，请重试这条命令"
        )

    # --- 2. 解锁密码库 ---------------------------------------------------
    vault_obj = None
    try:
        vault_obj = vault.open_vault()
    except vault.VaultError:
        status, detail = _launch("unlock", {})
        if status != "ok":
            code = _setup_failed(status, detail, "unlock")
            if code == protocol.EXIT_CONFIG:
                return protocol.emit(
                    protocol.EXIT_LOCKED, "密码库无法自动解锁",
                    hint=(f"密码库无法自动解锁。请告诉用户在自己的终端里执行：\n"
                          f"{_manual_cmd('unlock')}"),
                )
            return code
        try:
            vault_obj = vault.open_vault()
        except vault.VaultError as exc:
            return protocol.emit(protocol.EXIT_LOCKED, str(exc))

    # --- 3. 主机必须已配置 -----------------------------------------------
    host = store.get(name)
    if host is None:
        status, detail = _launch("add_host", {"host_name": name})
        if status != "ok":
            return _setup_failed(status, detail, f"config")
        return protocol.emit(
            protocol.EXIT_HOST_ADDED, f"已添加主机 {name}，请重试这条命令"
        )

    # --- 4. 拿密码 -------------------------------------------------------
    password = vault_obj.get(name) if vault_obj else None
    if not password and not host.key_file:
        status, detail = _launch("add_host", {"host_name": name})
        if status != "ok":
            return _setup_failed(status, detail, "config")
        return protocol.emit(
            protocol.EXIT_CONFIGURED, f"已补充 {name} 的密码，请重试这条命令"
        )

    # --- 5. 执行 ---------------------------------------------------------
    redactor = Redactor([password] if password else [])
    safe_cmd = redactor.clean(command)

    reason = host.policy.check(command, allow_shell=host.allow_shell)
    if reason:
        audit.write("run.denied", host=name, user=host.user, command=safe_cmd,
                    ok=False, error=reason)
        _warn(f"[sshhh] 命令被策略拒绝：{reason}")
        return 1

    timeout = _float_opt(opts, "timeout")
    stdin_data = _stdin_data(opts)
    max_bytes, tail_lines = _output_opts(opts)

    client = Client(host, password, store.Settings(), redactor)
    try:
        with client:
            result = client.run(
                command, stdin_data=stdin_data, timeout=timeout,
                use_sudo=bool(opts.get("sudo")) or host.sudo,
            )
    except TransportError as exc:
        audit.write("run", host=name, user=host.user, command=safe_cmd,
                    ok=False, error=str(exc))
        _warn(f"[sshhh] {exc}")
        return protocol.EXIT_NETWORK

    stdout_text, out_info = output.shape(
        result.stdout, max_bytes=max_bytes, tail_lines=tail_lines)
    stderr_text, err_info = output.shape(
        result.stderr, max_bytes=max_bytes, tail_lines=tail_lines)

    sys.stdout.write(stdout_text)
    if stdout_text and not stdout_text.endswith("\n") and sys.stdout.isatty():
        sys.stdout.write("\n")
    sys.stdout.flush()
    if stderr_text:
        sys.stderr.write(stderr_text)
        sys.stderr.flush()

    truncated = out_info["truncated"] or err_info["truncated"]
    audit.write("run", host=name, user=host.user, command=safe_cmd,
                exit_code=result.exit_code, duration_ms=result.duration_ms,
                ok=result.exit_code == 0, truncated=truncated,
                original_bytes=max(out_info["original_bytes"],
                                   err_info["original_bytes"]))
    return result.exit_code


def cmd_list(argv: list[str]) -> int:
    from lib import store, vault

    _parse(argv, set())
    hosts = store.load()
    if not hosts:
        _say("还没有配置任何主机。")
        _say(f"对 AI 说「连一下 <名称>」即可触发配置，或手动执行：{_manual_cmd('config')}")
        return 0

    try:
        v = vault.open_vault()
        have_pw = set(v.names())
    except vault.VaultError:
        have_pw = set()

    width = max(len("名称"), *(len(n) for n in hosts))
    _say(f"{'名称'.ljust(width)}  地址                        认证    备注")
    _say("-" * (width + 42))
    for n, h in sorted(hosts.items()):
        if h.key_file:
            auth = "密钥"
        elif n in have_pw:
            auth = "密码"
        else:
            auth = "缺密码"
        addr = f"{h.user}@{h.host}:{h.port}"
        _say(f"{n.ljust(width)}  {addr.ljust(26)}  {auth.ljust(6)}  {h.description}")
    return 0


def cmd_test(argv: list[str]) -> int:
    from lib import audit, protocol, store, vault
    from lib.transport import Client, TransportError

    _, pos = _parse(argv, set())
    if not pos:
        raise UsageError("用法：sshhh test <主机>")
    name = pos[0]

    host = store.get(name)
    if host is None:
        return _unknown_host(name)

    try:
        v = vault.open_vault()
    except vault.VaultError as exc:
        return protocol.emit(protocol.EXIT_LOCKED, str(exc))
    password = v.get(name)

    target = f"{host.user}@{host.host}:{host.port}"
    _say(f"连接 {name} ({target}) ...")
    client = Client(host, password, store.Settings())
    try:
        with client:
            r = client.run("echo __SSHHH_OK__; uname -s; hostname", timeout=20)
    except TransportError as exc:
        audit.write("test", host=name, user=host.user, command=target,
                    ok=False, error=str(exc))
        _warn(f"[sshhh] 连接失败：{exc}")
        return 4

    if "__SSHHH_OK__" not in r.stdout:
        error = "连接建立但测试命令未返回预期输出"
        audit.write("test", host=name, user=host.user, command=target,
                    ok=False, error=error, duration_ms=r.duration_ms)
        _warn(f"[sshhh] {error}")
        return 4
    audit.write("test", host=name, user=host.user, command=target,
                duration_ms=r.duration_ms)
    _say(f"[ok] 连接成功（{r.duration_ms} ms）")
    for line in r.stdout.splitlines():
        if line and line != "__SSHHH_OK__":
            _say(f"     {line}")
    return 0


def _inside(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _guard_local_path(direction: str, path: str) -> str | None:
    """文件通道的本地路径约束。返回拒绝原因，None 表示放行。

    `put` 的本地源由调用方指定，`get` 的本地目标也是 —— 两边都不设防的话，
    `get prod /etc/shadow ~/.sshhh/hosts.toml` 能把密码库/清单写坏（DoS），
    `put prod ~/.sshhh/vault.enc /tmp/x` 能把整库密文送到远端（#32）。
    realpath 归一之后再判断，防止用符号链接或 `..` 绕过去。
    """
    target = Path(os.path.realpath(os.path.expanduser(path)))
    data_dir = Path(os.path.realpath(paths.data_dir()))
    tmp_dir = Path(os.path.realpath(paths.data_dir() / "tmp"))

    if direction == "get":
        if _inside(target, tmp_dir):
            return None
        if _inside(target, data_dir):
            return (f"下载目标不能落在 sshhh 数据目录内（{data_dir}）："
                    "那里是密码库、主机清单和指纹库")
        cwd = Path(os.path.realpath(os.getcwd()))
        if _inside(target, cwd):
            return None
        return (f"下载目标必须在当前目录（{cwd}）或其子目录，"
                f"或 {tmp_dir} 内；收到的是 {target}")

    if _inside(target, data_dir):
        return (f"上传源不能是 sshhh 数据目录里的文件（{data_dir}）："
                "那里是密码库、主机清单和指纹库")
    if not target.exists():
        return f"上传源不存在：{target}"
    if not target.is_file():
        return f"上传源不是普通文件：{target}"
    return None


def _transfer(argv: list[str], direction: str) -> int:
    from lib import audit, protocol, store, vault
    from lib.transport import Client, TransportError

    opts, pos = _parse(argv, {"max-bytes", "timeout"})
    if len(pos) < 3:
        raise UsageError(f"用法：sshhh {direction} <主机> <本地> <远端>")
    name, a, b = pos[0], pos[1], pos[2]

    host = store.get(name)
    if host is None:
        return _unknown_host(name)
    try:
        v = vault.open_vault()
    except vault.VaultError as exc:
        return protocol.emit(protocol.EXIT_LOCKED, str(exc))

    local = os.path.expanduser(a if direction == "put" else b)
    remote = b if direction == "put" else a
    # 审计里按数据流向写：put 是「本地 → 远端」，get 反过来，一眼能看出往哪走
    summary = (f"put {local} -> {remote}" if direction == "put"
               else f"get {remote} -> {local}")

    # 文件通道必须和 run 一样过策略。只配了命令白名单的主机，默认连传文件都不许：
    # 否则「只允许 df -h」的机器照样能被 get /etc/shadow 掏空。
    reason = host.policy.check_transfer(direction, remote)
    if reason:
        audit.write("transfer.denied", host=name, user=host.user,
                    command=summary, ok=False, error=reason)
        _warn(f"[sshhh] 文件传输被策略拒绝：{reason}")
        return 1

    reason = _guard_local_path(direction, local)
    if reason:
        audit.write("transfer.denied", host=name, user=host.user,
                    command=summary, ok=False, error=reason)
        _warn(f"[sshhh] 本地路径被拒绝：{reason}")
        return 1

    cap, has_cap = _int_opt(opts, "max-bytes", 0, allow_zero=True)
    max_bytes = cap if has_cap else None
    timeout = _float_opt(opts, "timeout")

    client = Client(host, v.get(name), store.Settings())
    try:
        with client:
            if direction == "put":
                size = client.put_file(local, remote, max_bytes=max_bytes,
                                       timeout=timeout)
            else:
                size = client.get_file(remote, local, max_bytes=max_bytes,
                                       timeout=timeout)
    except TransportError as exc:
        audit.write(f"transfer.{direction}", host=name, user=host.user,
                    command=summary, ok=False, error=str(exc))
        _warn(f"[sshhh] {exc}")
        return 4
    except OSError as exc:
        audit.write(f"transfer.{direction}", host=name, user=host.user,
                    command=summary, ok=False, error=str(exc))
        _warn(f"[sshhh] 文件传输失败：{exc}")
        return 4
    audit.write(f"transfer.{direction}", host=name, user=host.user,
                command=f"{summary}（{size} 字节）")
    _say(f"[ok] {direction} 完成：{a} -> {b}（{size} 字节）")
    return 0


def cmd_put(argv: list[str]) -> int:
    return _transfer(argv, "put")


def cmd_get(argv: list[str]) -> int:
    return _transfer(argv, "get")


def cmd_config(argv: list[str]) -> int:
    """手动配置入口：没有库就做完整初始化，有库就加一台主机。

    `--here` 表示在当前终端里直接跑向导，不弹新窗口。给「窗口总是被
    外部杀掉」的场景留的退路 —— 全程在用户自己的终端里完成，没有子进程
    可以被别人带走。
    """
    from lib import vault

    opts, _ = _parse(argv, set())
    here = bool(opts.get("here"))

    if not paths.vault_file().exists():
        task, done = "setup", "[ok] 初始化完成"
    else:
        try:
            vault.open_vault()
            task, done = "add_host", "[ok] 已添加主机"
        except vault.VaultError:
            task, done = "unlock", "[ok] 密码库已解锁"

    if here:
        return _run_here(task, {})

    status, detail = _launch(task, {})
    if status != "ok":
        return _setup_failed(status, detail, "config")
    if task == "add_host":
        _say(f"[ok] 已添加主机 {detail.get('host', '')}".rstrip())
    else:
        _say(done)
    return 0


def cmd_setpass(argv: list[str]) -> int:
    from lib import audit, store, vault

    _, pos = _parse(argv, set())
    if not pos:
        raise UsageError("用法：sshhh setpass <主机>")
    name = pos[0]

    host = store.get(name)
    if host is None:
        return _unknown_host(name)

    try:
        vault.open_vault()
    except vault.VaultError:
        status, detail = _launch("unlock", {})
        if status != "ok":
            code = _setup_failed(status, detail, "unlock")
            audit.write("setpass", host=name, user=host.user, ok=False,
                        error=f"密码库未解锁（{status}），密码未修改")
            return code

    status, detail = _launch("add_host", {"host_name": name, "reset_password": True})
    if status != "ok":
        code = _setup_failed(status, detail, "config")
        audit.write("setpass", host=name, user=host.user, ok=False,
                    error=str(detail.get("error") or status))
        return code
    audit.write("setpass", host=name, user=host.user)
    _say(f"[ok] {name} 的密码已更新")
    return 0


def cmd_unlock(argv: list[str]) -> int:
    from lib import audit, vault

    _parse(argv, set())
    if not paths.vault_file().exists():
        audit.write("unlock", ok=False, error="尚未初始化")
        _warn("[sshhh] 还没有初始化，请先执行 config")
        return 3
    try:
        vault.open_vault()
    except vault.VaultError as exc:
        # 自动解锁失败本身就是安全相关事件，先记一笔再让用户输入
        audit.write("unlock", ok=False, command="钥匙串自动解锁失败", error=str(exc))
    else:
        audit.write("unlock", ok=True, command="钥匙串自动解锁")
        _say("[ok] 密码库当前可自动解锁，无需操作")
        return 0

    status, detail = _launch("unlock", {})
    if status != "ok":
        code = _setup_failed(status, detail, "unlock")
        audit.write("unlock", ok=False, command="等待用户输入",
                    error=str(detail.get("error") or status))
        return code
    audit.write("unlock", ok=True, command="用户输入")
    _say("[ok] 已解锁")
    return 0


def cmd_status(argv: list[str]) -> int:
    from lib import store, vault

    _parse(argv, set())
    _say(f"数据目录：{paths.data_dir()}")
    _say(f"密码库：  {paths.vault_file()}" +
         ("（存在）" if paths.vault_file().exists() else "（不存在）"))
    _say(f"主机清单：{paths.hosts_file()}" +
         ("（存在）" if paths.hosts_file().exists() else "（不存在）"))

    if paths.vault_file().exists():
        try:
            v = vault.open_vault()
            _say(f"[ok] 密码库可自动解锁，含 {len(v.names())} 条密码")
        except vault.VaultError as exc:
            _say(f"[!!] 密码库无法自动解锁：{exc}")

    hosts = store.load()
    _say(f"[--] 已配置 {len(hosts)} 台主机")
    for n, h in sorted(hosts.items()):
        _say(f"     {n}: {h.user}@{h.host}:{h.port} {h.description}")

    from lib import console

    active = console.find_active()
    if active is not None:
        _say(f"[!!] 有一个配置窗口正在运行（pid {active[1]}），用户可能正在里面输入")
    return 0


def cmd_audit(argv: list[str]) -> int:
    from lib import audit

    opts, _ = _parse(argv, {"n"})
    limit = int(opts.get("n", 20))
    records = audit.tail(limit)
    if not records:
        _say("暂无审计记录")
        return 0
    for rec in records:
        flag = "ok " if rec.get("ok") else "ERR"
        ts = str(rec.get("ts", ""))[5:19].replace("T", " ")
        cmd = rec.get("command", "")
        if len(cmd) > 80:
            # vault.open 的命令行摘要很长，展示时收一收；完整内容在 audit.log 里
            cmd = cmd[:80] + "…"
        extra = f"  « {cmd}" if cmd else ""
        err = f"  ({rec['error']})" if rec.get("error") else ""
        _say(f"{flag} {ts}  {rec.get('action')} {rec.get('host')}{extra}{err}")
    return 0


def cmd_migrate(argv: list[str]) -> int:
    """从旧版 sshx 项目（agentssh）迁移主机与密码。"""
    import tomllib

    from lib import audit, store, vault

    _, pos = _parse(argv, set())
    if not pos:
        raise UsageError("用法：sshhh migrate <旧项目目录，例如 D:/work/agentssh>")

    old_dir = Path(pos[0]).expanduser()
    old_vault_path = old_dir / "vault.enc"
    old_cfg = old_dir / "sshx.toml"

    if not old_vault_path.exists():
        audit.write("migrate", ok=False, command=str(old_dir),
                    error="找不到旧密码库")
        _warn(f"[sshhh] 找不到旧密码库：{old_vault_path}")
        return 3
    if paths.vault_file().exists():
        audit.write("migrate", ok=False, command=str(old_dir),
                    error="目标位置已有密码库")
        _warn(f"[sshhh] 目标位置已有密码库：{paths.vault_file()}")
        _warn("[sshhh] 请先备份并移走它，再执行迁移")
        return 3

    # 旧库的主密码可能存在旧的钥匙串条目里（服务名 sshx）
    master = vault.keyring_load(old_vault_path, service="sshx")
    if not master:
        master = os.environ.get("SSHHH_MASTER")
    if not master:
        _say("需要旧配置的主密码来解密原有密码库")
        master = vault.prompt_master("旧主密码")

    try:
        old_v = vault.Vault.open(old_vault_path, master=master, allow_keyring=False)
    except vault.VaultError:
        audit.write("migrate", ok=False, command=str(old_dir),
                    error="旧主密码错误，未做任何修改")
        _warn("[sshhh] 主密码错误，无法读取旧密码库")
        return 3

    paths.ensure_data_dir()
    new_v = vault.Vault.create(paths.vault_file(), master)
    for name in old_v.names():
        value = old_v.get(name)
        if value:
            new_v.set(name, value)

    migrated: list[str] = []
    if old_cfg.exists():
        raw = tomllib.loads(old_cfg.read_text(encoding="utf-8"))
        for name, item in (raw.get("hosts") or {}).items():
            if not isinstance(item, dict) or not item.get("host"):
                continue
            host = store.Host(
                name=name,
                host=str(item["host"]),
                user=str(item.get("user", "root")),
                port=int(item.get("port", 22)),
                description=str(item.get("description", "")),
                sudo=bool(item.get("sudo", False)),
                key_file=item.get("key_file") or None,
            )
            store.upsert_host(host)
            pol = item.get("policy") or {}
            allow = [str(x) for x in (pol.get("allow") or [])]
            deny = [str(x) for x in (pol.get("deny") or [])]
            allow_put = [str(x) for x in (pol.get("allow_put") or [])]
            allow_get = [str(x) for x in (pol.get("allow_get") or [])]
            deny_put = [str(x) for x in (pol.get("deny_put") or [])]
            deny_get = [str(x) for x in (pol.get("deny_get") or [])]
            if allow or deny or allow_put or allow_get or deny_put or deny_get:
                store.set_policy(name, allow, deny, allow_put=allow_put,
                                 allow_get=allow_get, deny_put=deny_put,
                                 deny_get=deny_get)
            migrated.append(name)

    if vault.keyring_save(paths.vault_file(), master):
        _say("[ok] 主密码已存入系统凭据管理器")
    else:
        _warn("[!] 凭据管理器不可用，之后需设置环境变量 SSHHH_MASTER")

    audit.write("migrate", command=f"{old_dir}（{len(new_v.names())} 条密码 / "
                                   f"{len(migrated)} 台主机）")
    _say(f"[ok] 已迁移 {len(new_v.names())} 条密码、{len(migrated)} 台主机"
         f"（{', '.join(migrated) or '无'}）")
    _say(f"     新数据目录：{paths.data_dir()}")
    _say("     旧目录可以保留不动，确认无误后再自行删除")
    return 0


COMMANDS = {
    "run": cmd_run,
    "list": cmd_list,
    "ls": cmd_list,
    "test": cmd_test,
    "put": cmd_put,
    "get": cmd_get,
    "config": cmd_config,
    "setpass": cmd_setpass,
    "unlock": cmd_unlock,
    "status": cmd_status,
    "audit": cmd_audit,
    "setup": cmd_setup,
    "migrate": cmd_migrate,
}


def main(argv: list[str] | None = None) -> int:
    _setup_io()
    args = list(sys.argv[1:] if argv is None else argv)

    if not args or args[0] in ("-h", "--help", "help"):
        _say(USAGE.format(data=paths.data_dir()))
        return 0
    if args[0] in ("-V", "--version", "version"):
        _say("sshhh 1.0.0")
        return 0

    cmd, rest = args[0], args[1:]
    handler = COMMANDS.get(cmd)
    if handler is None:
        _warn(f"未知命令：{cmd}")
        _say(USAGE.format(data=paths.data_dir()))
        return 2

    try:
        if cmd != "setup":
            from lib import runtime

            try:
                runtime.ensure()
            except runtime.PythonTooOldError as exc:
                from lib import protocol

                _warn(f"[sshhh] {exc}")
                return protocol.emit(
                    protocol.EXIT_NO_RUNTIME, str(exc), hint=_python_too_old_hint()
                )
            except runtime.RuntimeError_ as exc:
                from lib import protocol

                _warn(f"[sshhh] {exc}")
                return protocol.emit(
                    protocol.EXIT_NO_RUNTIME, str(exc), hint=_deps_hint()
                )
        return handler(rest)
    except UsageError as exc:
        _warn(f"[sshhh] {exc}")
        return 2
    except LockTimeout as exc:
        # 另一个 sshhh 进程正在配置。可重试，不是内部错误。
        _warn(f"[sshhh] {exc}")
        return 3
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        _warn("\n[sshhh] 已取消")
        return 130
    except Exception as exc:  # noqa: BLE001
        from lib import protocol

        _warn(f"[sshhh] 内部错误：{exc}")
        return protocol.EXIT_CONFIG


if __name__ == "__main__":
    sys.exit(main())
