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

执行层（agent 调用）：
  run <主机> <命令...>     执行命令（退出码透传）
  list                    列出已配置的主机
  test <主机>              连通性测试
  put <主机> <本地> <远端>   上传文件
  get <主机> <远端> <本地>   下载文件
  status                  查看整体状态（自诊断）

管理层（用户本人执行；旧命令保留别名）：
  manage setup            只安装运行环境
  manage hosts            列出主机清单（同 list）
  manage setpass <主机>    修改某台主机的密码
  manage unlock           重新输入主密码
  manage policy <主机>     查看该主机的生效策略
  manage reseal            手编 hosts.toml 后重新签名
  manage keygen <主机> [--force]  生成密钥（私钥入密码库，打印公钥）
  manage keyimport <主机> [文件]  导入已有私钥到密码库
  manage keyshow <主机>    显示该主机的公钥行与指纹
  manage audit [-n N] [--all] 查看审计记录（--all 含解密留痕）
  manage harden <主机> --check 只读探测远端可加固性
  manage migrate <旧目录>  从旧版 sshx 项目迁移主机和密码
  config [--here]         打开配置窗口；加 --here 则在当前终端里配置

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
_LONG_BOOL_FLAGS = frozenset({"sudo", "all"})


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
        # 弹窗不可用有多种原因，文案必须对症（#33）：非 Windows 的 agent shell
        # 没有 tty，根本没有窗口可等；.no-window 标记说明这个环境弹窗撑不住。
        # 退出码一律 12（TIMEOUT）不变契约，但 hint 不再提「窗口可能还开着」。
        if paths.no_window_marker().exists():
            return "gone", {}  # 弹窗链路已知撑不住，复用同款指引
        return "unavailable", {}
    return console.launch(task, payload, _setup_timeout(), _handoff_seconds())


def _setup_failed(status: str, detail: dict, manual_sub: str,
                  nonce: str = "") -> int:
    """把配置窗口的非成功结果翻译成协议状态码。

    `nonce`：run 路径传入本次调用的 nonce，让 agent 只认带同一标识的状态行。
    """
    from lib import protocol

    if status == "unavailable":
        return protocol.emit(
            protocol.EXIT_TIMEOUT,
            "这里没有可用的交互窗口环境，配置没有完成",
            hint=(
                "这台机器（或当前调用环境）无法弹出配置窗口（非图形环境，"
                "或 agent 的非交互终端）。\n"
                "不要提「窗口」——这里根本没有窗口。请告诉用户在自己的终端里"
                "执行下面的命令，跟着提示设置主密码和服务器信息：\n"
                f"{_manual_cmd('config --here')}\n"
                "配置完成后重试原命令即可。"
            ),
            nonce=nonce,
        )
    if status == "cancel":
        return protocol.emit(
            protocol.EXIT_CANCELLED, "用户取消了配置，未做任何修改", nonce=nonce
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
            nonce=nonce,
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
            nonce=nonce,
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
                nonce=nonce,
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
            nonce=nonce,
        )
    err = detail.get("error") or "配置窗口返回错误"
    return protocol.emit(
        protocol.EXIT_CONFIG, str(err),
        hint=("如果配置窗口反复异常退出，可以直接在用户自己的终端里执行下面的命令，"
              "全程不弹新窗口：\n"
              f"{_manual_cmd('config --here')}"),
        nonce=nonce,
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

    # run 是唯一混杂远端输出的命令：远端可以在 stderr 里伪造 SSHHH_STATUS
    # 劫持 agent（#36）。所以本次调用先打一行本地 nonce，协议状态行全部
    # 带上它 —— 远端在本地输出之后才开口，抢不到先手。
    nonce = protocol.new_nonce()
    print(f"SSHHH_INVOCATION: {nonce}", file=sys.stderr)

    opts, pos = _parse(argv, {"timeout", "stdin", "stdin-file",
                              "max-bytes", "tail"})
    if not pos:
        raise UsageError('用法：sshhh run <主机> "<命令>"')
    name = pos[0]
    command = " ".join(pos[1:]).strip()
    if not command:
        raise UsageError('缺少要执行的命令，例如：sshhh run prod "df -h"')

    # 选项本身先校验一遍：参数写错就报 2，不要先去弹配置窗口
    timeout = _float_opt(opts, "timeout")
    max_bytes, tail_lines = _output_opts(opts)

    # --- 1. 没有密码库：先配置 -------------------------------------------
    if not paths.vault_file().exists():
        status, detail = _launch("setup", {})
        if status != "ok":
            return _setup_failed(status, detail, "config", nonce=nonce)
        return protocol.emit(
            protocol.EXIT_CONFIGURED, "已经完成初始化配置，请重试这条命令",
            nonce=nonce,
        )

    # --- 2. 解锁密码库 ---------------------------------------------------
    vault_obj = None
    try:
        vault_obj = vault.open_vault()
    except vault.VaultError:
        status, detail = _launch("unlock", {})
        if status != "ok":
            code = _setup_failed(status, detail, "unlock", nonce=nonce)
            if code == protocol.EXIT_CONFIG:
                return protocol.emit(
                    protocol.EXIT_LOCKED, "密码库无法自动解锁",
                    hint=(f"密码库无法自动解锁。请告诉用户在自己的终端里执行：\n"
                          f"{_manual_cmd('unlock')}"),
                    nonce=nonce,
                )
            return code
        try:
            vault_obj = vault.open_vault()
        except vault.VaultError as exc:
            return protocol.emit(protocol.EXIT_LOCKED, str(exc), nonce=nonce)

    # --- 3. 主机必须已配置 -----------------------------------------------
    try:
        host = store.get(name)
    except store.StoreError as exc:
        # 清单解析失败或完整性签名失效（#18）：建连前中止，
        # 绝不按一份被改过的清单放行命令
        return protocol.emit(protocol.EXIT_CONFIG, str(exc), nonce=nonce)
    if host is None:
        status, detail = _launch("add_host", {"host_name": name})
        if status != "ok":
            return _setup_failed(status, detail, f"config", nonce=nonce)
        return protocol.emit(
            protocol.EXIT_HOST_ADDED, f"已添加主机 {name}，请重试这条命令",
            nonce=nonce,
        )

    # --- 4. 取凭据：vault 密钥优先，密码兜底（#3 基线） -------------------
    # vault_obj 到这里必然非 None：第 2 步失败早已走 unlock 路径并 return
    password = vault_obj.get(name)
    key_pem = vault_obj.get(f"key:{name}")
    if not password and not key_pem:
        if host.key_file:
            # key_file 托管旁路已封（#18）：磁盘路径上的私钥不再参与认证
            return protocol.emit(
                protocol.EXIT_CONFIG,
                f"主机 {name} 只配置了已废弃的 key_file 字段，需要把私钥"
                "导入密码库后才能连接",
                hint=("请告诉用户在自己的终端里执行：\n"
                      f"{_manual_cmd(f'manage keyimport {name}')}\n"
                      "（会自动使用主机里遗留的 key_file 路径）"),
                nonce=nonce,
            )
        status, detail = _launch("add_host", {"host_name": name})
        if status != "ok":
            return _setup_failed(status, detail, "config", nonce=nonce)
        return protocol.emit(
            protocol.EXIT_CONFIGURED, f"已补充 {name} 的凭据，请重试这条命令",
            nonce=nonce,
        )

    # --- 5. 执行 ---------------------------------------------------------
    # 脱敏用 vault 全量值而不是只有本机密码（#34 I9）：A 机的密码出现在
    # B 机的输出里（jump host 场景、配置文件里贴了另一台的密码）同样要替换。
    redactor = Redactor(vault_obj.values())
    safe_cmd = redactor.clean(command)

    # 认证方式进审计：拒绝类记录写「预期的主认证方式」；真实连接的记录
    # 在连接后按实际使用的认证写（#3：key / password，回落加 fallback）
    auth = "key" if key_pem else "password"

    reason = host.policy.check(command, allow_shell=host.allow_shell)
    if reason:
        audit.write("run.denied", host=name, user=host.user, command=safe_cmd,
                    ok=False, error=reason, auth=auth)
        _warn(f"[sshhh] 命令被策略拒绝：{reason}")
        return 1

    # stdin 放到策略检查之后再读：被拒的命令不该先把调用方的管道吃掉
    stdin_data = _stdin_data(opts)

    client = Client(host, password, store.Settings(), redactor, key_pem=key_pem)
    try:
        with client:
            result = client.run(
                command, stdin_data=stdin_data, timeout=timeout,
                use_sudo=bool(opts.get("sudo")) or host.sudo,
            )
    except TransportError as exc:
        audit.write("run", host=name, user=host.user, command=safe_cmd,
                    ok=False, error=str(exc), auth=auth)
        _warn(f"[sshhh] {exc}")
        return protocol.EXIT_NETWORK

    if client.auth_fallback:
        _warn("[sshhh] 注意：密钥认证被服务器拒绝，本次连接回落到了密码"
              "（已写入审计）。若这不是预期，请检查服务器上的公钥是否还在")

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
                                   err_info["original_bytes"]),
                auth=client.auth_used or auth,
                fallback="key" if client.auth_fallback else "")
    return result.exit_code


def cmd_list(argv: list[str]) -> int:
    from lib import store, vault

    _parse(argv, set())
    # 只读展示用免验签读取（load_unverified）：清单签名失效时用户恰恰需要
    # 用 list 看看里面有什么；验签由 run / test 等强制路径负责
    try:
        hosts = store.load_unverified()
    except store.StoreError as exc:
        _warn(f"[sshhh] {exc}")
        return 3
    if not hosts:
        _say("还没有配置任何主机。")
        _say(f"对 AI 说「连一下 <名称>」即可触发配置，或手动执行：{_manual_cmd('config')}")
        return 0

    try:
        v = vault.open_vault()
        have_pw = set(v.names())
        # key_names() 带 key: 前缀，按裸主机名比对需要剥掉
        have_keys = {n.removeprefix("key:") for n in v.key_names()}
    except vault.VaultError:
        have_pw = set()
        have_keys = set()

    width = max(len("名称"), *(len(n) for n in hosts))
    _say(f"{'名称'.ljust(width)}  地址                        认证    备注")
    _say("-" * (width + 42))
    legacy = False
    for n, h in sorted(hosts.items()):
        if n in have_keys and n in have_pw:
            auth = "密钥+密码"
        elif n in have_keys:
            auth = "密钥"
        elif n in have_pw:
            auth = "密码"
        elif h.key_file:
            auth = "key_file*"  # 遗留字段已不参与认证（#18），提示迁移
            legacy = True
        else:
            auth = "缺凭据"
        addr = f"{h.user}@{h.host}:{h.port}"
        _say(f"{n.ljust(width)}  {addr.ljust(26)}  {auth.ljust(10)}  {h.description}")
    if legacy:
        _say("")
        _say("* key_file 字段已不再参与认证（#18）："
             "请执行 manage keyimport <主机> 把私钥导入密码库")
    return 0


def cmd_test(argv: list[str]) -> int:
    from lib import audit, protocol, store, vault
    from lib.redact import Redactor
    from lib.transport import Client, TransportError

    _, pos = _parse(argv, set())
    if not pos:
        raise UsageError("用法：sshhh test <主机>")
    name = pos[0]

    # 先解锁再读清单（#39）：store.get 的验签依赖密码库解锁后绑定的 MAC
    # 密钥，全新进程里锁着读等于不验 —— 与 run 同一纪律，所有连接类命令
    # 都必须「先解锁、后读清单」。
    try:
        v = vault.open_vault()
    except vault.VaultError as exc:
        return protocol.emit(protocol.EXIT_LOCKED, str(exc))

    try:
        host = store.get(name)
    except store.StoreError as exc:
        return protocol.emit(protocol.EXIT_CONFIG, str(exc))
    if host is None:
        return _unknown_host(name)

    password = v.get(name)

    # 探测命令是脚本自己写死的，但同样要过策略（#34 I6）：用户把主机配成
    # 白名单模式（「只许跑 df -h」）时，test 无权在这台机器上另跑别的命令。
    # 探测拆成三条独立命令，避免为了拼一行而依赖 shell 元字符。
    probes = ["echo __SSHHH_OK__", "uname -s", "hostname"]
    for probe in probes:
        reason = host.policy.check(probe, allow_shell=host.allow_shell)
        if reason:
            audit.write("test.denied", host=name, user=host.user,
                        command=probe, ok=False, error=reason)
            _warn(f"[sshhh] 探测命令被策略拒绝：{reason}")
            if host.policy.allow:
                _warn("[sshhh] 该主机处于白名单模式，test 的探测命令未获放行；"
                      "请直接 run 一条白名单内的命令验证连通")
            return 1

    target = f"{host.user}@{host.host}:{host.port}"
    _say(f"连接 {name} ({target}) ...")
    redactor = Redactor(v.values())
    key_pem = v.get(f"key:{name}")
    auth = "key" if key_pem else "password"
    client = Client(host, password, store.Settings(), redactor, key_pem=key_pem)
    try:
        with client:
            r = client.run(probes[0], timeout=20)
            if "__SSHHH_OK__" not in r.stdout:
                error = "连接建立但测试命令未返回预期输出"
                audit.write("test", host=name, user=host.user, command=target,
                            ok=False, error=error, duration_ms=r.duration_ms,
                            auth=client.auth_used or auth,
                            fallback="key" if client.auth_fallback else "")
                _warn(f"[sshhh] {error}")
                return 4
            info = ""
            for probe in probes[1:]:
                rr = client.run(probe, timeout=20)
                info += rr.stdout
    except TransportError as exc:
        audit.write("test", host=name, user=host.user, command=target,
                    ok=False, error=str(exc), auth=auth)
        _warn(f"[sshhh] 连接失败：{exc}")
        return 4

    if client.auth_fallback:
        _warn("[sshhh] 注意：密钥认证被服务器拒绝，本次连接回落到了密码"
              "（已写入审计）")
    audit.write("test", host=name, user=host.user, command=target,
                duration_ms=r.duration_ms, auth=client.auth_used or auth,
                fallback="key" if client.auth_fallback else "")
    _say(f"[ok] 连接成功（{r.duration_ms} ms）")
    for line in info.splitlines():
        if line:
            _say(f"     {line}")
    return 0


def _norm(path: str | Path) -> str:
    """归一成本地可比较的绝对路径：展开 ~、解析符号链接、Windows 上统一大小写。"""
    return os.path.normcase(os.path.realpath(os.path.expanduser(str(path))))


def _inside(child: str, parent: str) -> bool:
    if child == parent:
        return True
    return child.startswith(parent.rstrip(os.sep) + os.sep)


def _guard_local_path(direction: str, path: str) -> str | None:
    """文件通道的本地路径约束。返回拒绝原因，None 表示放行。

    `put` 的本地源由调用方指定，`get` 的本地目标也是 —— 两边都不设防的话，
    `get prod /etc/shadow ~/.sshhh/hosts.toml` 能把密码库/清单写坏（DoS），
    `put prod ~/.sshhh/vault.enc /tmp/x` 能把整库密文送到远端（#32）。
    realpath 归一之后再判断，防止用符号链接、`..` 或大小写变体绕过去。
    """
    target = _norm(path)
    data_dir = _norm(paths.data_dir())
    tmp_dir = _norm(paths.data_dir() / "tmp")

    if direction == "get":
        if _inside(target, tmp_dir):
            return None
        if _inside(target, data_dir):
            return (f"下载目标不能落在 sshhh 数据目录内（{data_dir}）："
                    "那里是密码库、主机清单和指纹库")
        try:
            cwd = _norm(os.getcwd())
        except OSError:
            cwd = ""
        if cwd and _inside(target, cwd):
            return None
        return (f"下载目标必须在当前目录（{cwd or '（未知）'}）或其子目录，"
                f"或 {tmp_dir} 内；收到的是 {target}")

    if _inside(target, data_dir):
        return (f"上传源不能是 sshhh 数据目录里的文件（{data_dir}）："
                "那里是密码库、主机清单和指纹库")
    if not os.path.exists(target):
        return f"上传源不存在：{target}"
    if not os.path.isfile(target):
        return f"上传源不是普通文件：{target}"
    return None


def _transfer(argv: list[str], direction: str) -> int:
    from lib import audit, protocol, store, vault
    from lib.transport import Client, TransportError

    opts, pos = _parse(argv, {"max-bytes", "timeout"})
    if len(pos) < 3:
        raise UsageError(f"用法：sshhh {direction} <主机> <本地> <远端>")
    name, a, b = pos[0], pos[1], pos[2]

    # 先解锁再读清单（#39）：与 run 同一纪律，验签必须在 MAC 密钥绑定之后
    try:
        v = vault.open_vault()
    except vault.VaultError as exc:
        return protocol.emit(protocol.EXIT_LOCKED, str(exc))

    try:
        host = store.get(name)
    except store.StoreError as exc:
        return protocol.emit(protocol.EXIT_CONFIG, str(exc))
    if host is None:
        return _unknown_host(name)

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

    key_pem = v.get(f"key:{name}")
    auth = "key" if key_pem else "password"
    client = Client(host, v.get(name), store.Settings(), key_pem=key_pem)
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
                    command=summary, ok=False, error=str(exc), auth=auth)
        _warn(f"[sshhh] {exc}")
        return 4
    except OSError as exc:
        audit.write(f"transfer.{direction}", host=name, user=host.user,
                    command=summary, ok=False, error=str(exc), auth=auth)
        _warn(f"[sshhh] 文件传输失败：{exc}")
        return 4
    if client.auth_fallback:
        _warn("[sshhh] 注意：密钥认证被服务器拒绝，本次连接回落到了密码"
              "（已写入审计）")
    audit.write(f"transfer.{direction}", host=name, user=host.user,
                command=f"{summary}（{size} 字节）",
                auth=client.auth_used or auth,
                fallback="key" if client.auth_fallback else "")
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

    # 先解锁再读清单（#39）：后续 add_host 窗口会按清单里的主机信息改写，
    # 读到被篡改的清单就等于按篡改后的目标改密码
    try:
        vault.open_vault()
    except vault.VaultError:
        status, detail = _launch("unlock", {})
        if status != "ok":
            code = _setup_failed(status, detail, "unlock")
            audit.write("setpass", host=name, ok=False,
                        error=f"密码库未解锁（{status}），密码未修改")
            return code

    try:
        host = store.get(name)
    except store.StoreError as exc:
        return protocol.emit(protocol.EXIT_CONFIG, str(exc))
    if host is None:
        return _unknown_host(name)

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


def _backend_guidance() -> None:
    """无钥匙串环境（headless Linux / 容器）的针对性指引（#19）。"""
    from lib import vault

    if vault.keyring_available():
        return
    _say("     本环境没有可用的系统凭据库（无钥匙串 / Secret Service）")
    if vault.gpg_available():
        _say("     可用 gpg 加密文件后端：让用户在自己的终端里执行 "
             f"{_manual_cmd('unlock')}，主密码会加密存到 ~/.sshhh/master.gpg")
        _say("     （解密走本机 gpg 私钥 + gpg-agent；私钥带口令时需 agent 已缓存口令）")
    else:
        _say("     本机也没有 gpg。各平台后端可用性见 README「主密码后端」一节；")
        _say("     SSHHH_MASTER 环境变量可临时兜底，但 agent 能 printenv 读到，"
             "只做最后手段")


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
            _backend_guidance()

    try:
        hosts = store.load_unverified()
    except store.StoreError as exc:
        _say(f"[!!] 主机清单读取失败：{exc}")
        return 3
    _say(f"[--] 已配置 {len(hosts)} 台主机")
    for n, h in sorted(hosts.items()):
        _say(f"     {n}: {h.user}@{h.host}:{h.port} {h.description}")

    from lib import console

    active = console.find_active()
    if active is not None:
        _say(f"[!!] 有一个配置窗口正在运行（pid {active[1]}），用户可能正在里面输入")
    return 0


def cmd_audit(argv: list[str]) -> int:
    """查看审计记录（管理操作，本质是用户审查 agent 的行为）。

    展示层分流（#26）：默认隐藏 vault.open 解密留痕，正常使用只见业务动作；
    `--all` 看全量（文件本身全保真，一条不漏）。
    """
    from lib import audit

    opts, _ = _parse(argv, {"n"})
    limit, _ = _int_opt(opts, "n", 20, allow_zero=False)
    show_all = bool(opts.get("all"))
    records = audit.tail(limit, include_internal=show_all)
    if not records:
        _say("暂无审计记录")
        return 0
    if not show_all:
        _say("（vault.open 解密留痕默认隐藏；--all 查看全部）")
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
    # 3.9/3.10 没有标准库 tomllib；lib.store 顶部做过兼容 shim，复用它
    from lib.store import tomllib

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
    migrated: list[str] = []
    # 整个迁移（新密码库 + 主机 + 策略）放在一把锁里：中途被并发写打断会留下
    # 一半迁移过去的状态，比什么都不做更难查（#9）。
    from lib.lock import data_lock

    with data_lock(timeout=60):
        new_v = vault.Vault.create(paths.vault_file(), master)
        for name in old_v.names():
            value = old_v.get(name)
            if value:
                new_v.set(name, value)

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

    backend = vault.save_master_auto(paths.vault_file(), master)
    if backend == "keyring":
        _say("[ok] 主密码已存入系统凭据管理器")
    elif backend == "gpg":
        _say("[ok] 凭据管理器不可用；主密码已用 gpg 加密存到 ~/.sshhh/master.gpg")
    else:
        _warn("[!] 凭据管理器与 gpg 都不可用，之后需设置环境变量 SSHHH_MASTER")

    audit.write("migrate", command=f"{old_dir}（{len(new_v.names())} 条密码 / "
                                   f"{len(migrated)} 台主机）")
    _say(f"[ok] 已迁移 {len(new_v.names())} 条密码、{len(migrated)} 台主机"
         f"（{', '.join(migrated) or '无'}）")
    _say(f"     新数据目录：{paths.data_dir()}")
    _say("     旧目录可以保留不动，确认无误后再自行删除")
    return 0


def cmd_harden(argv: list[str]) -> int:
    """加固模式：只开接口，点到为止（#37，作者决策 2026-11-09）。

    `harden <主机> --check` 是**只读探测**：检查 sshd 是否 OpenSSH、shell 是否
    可用、authorized_keys 是否可写，输出可加固性报告与建议的 restrict 行。
    不装公钥、不部署服务端包装、不做回滚 —— 那是 #15 的完整实现，在观察名单，
    有真实需求或用户反馈再启动。
    """
    import re

    from lib import audit, protocol, store, vault
    from lib.redact import Redactor
    from lib.transport import Client, TransportError

    # --check 自己识别，不进全局解析器：harden 有位置参数，`harden prod --check`
    # 里的 --check 会被 _parse 当成「位置参数之后的未知长选项」留给远端
    check_flag = "--check" in argv
    opts, pos = _parse([a for a in argv if a != "--check"], set())
    if not pos or not check_flag:
        _warn("用法：sshhh manage harden <主机> --check（别名 sshhh harden）")
        _warn("目前只提供 --check 只读探测；完整加固（装公钥 / 服务端包装 / 回滚）"
              "尚未实现（#15，观察名单）")
        return 2
    name = pos[0]

    # 先解锁再读清单（#39）：与 run 同一纪律，验签必须在 MAC 密钥绑定之后
    try:
        v = vault.open_vault()
    except vault.VaultError as exc:
        return protocol.emit(protocol.EXIT_LOCKED, str(exc))

    try:
        host = store.get(name)
    except store.StoreError as exc:
        return protocol.emit(protocol.EXIT_CONFIG, str(exc))
    if host is None:
        return _unknown_host(name)

    key_pem = v.get(f"key:{name}")
    auth = "key" if key_pem else "password"
    password = v.get(name)

    # 探测命令与 test 同一纪律：过策略。脚本经 stdin 喂给 `bash -s`，
    # 命令行本身没有元字符；白名单主机不放行 `bash -s` 时如实拒绝。
    probe_cmd = "bash -s"
    reason = host.policy.check(probe_cmd, allow_shell=host.allow_shell)
    if reason:
        audit.write("harden.check", host=name, user=host.user,
                    command=probe_cmd, ok=False, error=reason, auth=auth)
        _warn(f"[sshhh] 探测命令被策略拒绝：{reason}")
        if host.policy.allow:
            _warn("[sshhh] 该主机处于白名单模式；探测命令未获放行")
        return 1

    # 探测脚本：只读检查 ~/.ssh 与 authorized_keys 的存在性与可写性。
    # keyw 的语义：文件可写，或文件不存在但目录可写（可创建）。
    script = (
        'd="$HOME/.ssh"; k="$d/authorized_keys"\n'
        'printf \'SSHHH_PROBE dir=%s dirw=%s keyw=%s\\n\' '
        '"$([ -d "$d" ] && echo 1 || echo 0)" '
        '"$([ -d "$d" ] && [ -w "$d" ] && echo 1 || echo 0)" '
        '"$([ -f "$k" ] && [ -w "$k" ] && echo 1 || echo 0; '
        '[ ! -e "$k" ] && [ -w "$d" ] && echo 1)"\n'
    )

    target = f"{host.user}@{host.host}:{host.port}"
    _say(f"[sshhh] 加固探测（只读）：{name} ({target})")
    client = Client(host, password, store.Settings(), Redactor(v.values()),
                    key_pem=key_pem)
    try:
        with client:
            banner = client.banner()
            r = client.run(probe_cmd, stdin_data=script, timeout=20)
    except TransportError as exc:
        audit.write("harden.check", host=name, user=host.user, command=probe_cmd,
                    ok=False, error=str(exc), auth=auth)
        _warn(f"[sshhh] 探测失败：{exc}")
        return 4
    if client.auth_fallback:
        _warn("[sshhh] 注意：密钥认证被服务器拒绝，本次连接回落到了密码"
              "（已写入审计）")

    checks: list[tuple[str, bool, str]] = []

    m = re.search(r"OpenSSH[_ ]([0-9][0-9.p]*)", banner)
    if m:
        checks.append(("sshd", True,
                       f"OpenSSH {m.group(1)}（支持 restrict / command=）"))
    elif banner:
        checks.append(("sshd", False,
                       f"非 OpenSSH：{banner[:60]}（受限 authorized_keys 语法不保证可用）"))
    else:
        checks.append(("sshd", False, "无法识别（服务器未提供 banner）"))

    fields: dict[str, str] = {}
    for line in r.stdout.splitlines():
        if line.startswith("SSHHH_PROBE "):
            for kv in line[len("SSHHH_PROBE "):].split():
                key, _, val = kv.partition("=")
                fields[key] = val
            break

    if not fields:
        checks.append(("shell", False,
                       "bash 存在但探测脚本没有返回结果（shell 受限或行为异常）"))
    else:
        checks.append(("shell", True, "bash 可用"))
        dir_ok = fields.get("dir") == "1"
        dir_w = fields.get("dirw") == "1"
        key_w = fields.get("keyw") == "1"
        checks.append(("~/.ssh 目录", dir_ok,
                       "存在" if dir_ok else "不存在（首次部署时创建即可，不算阻塞）"))
        checks.append(("authorized_keys 可写", key_w,
                       "可写或可创建" if key_w else
                       "不可写（需要先修权限或换部署方式）"))
        if not dir_w and dir_ok:
            checks.append(("~/.ssh 目录可写", False,
                           "目录存在但不可写，装公钥会失败"))

    _say("")
    ok_all = True
    for label, good, detail in checks:
        ok_all = ok_all and good
        _say(f"  {'[ok]' if good else '[!!]'} {label}：{detail}")
    audit.write("harden.check", host=name, user=host.user, command=probe_cmd,
                ok=ok_all, auth=client.auth_used or auth,
                fallback="key" if client.auth_fallback else "")
    _say("")
    if ok_all:
        _say("结论：具备可加固条件。")
    else:
        _say("结论：存在阻塞项（见上）。先把 [!!] 的项处理好再评估加固。")
    _say("建议的 restrict 行（#15 完整实现后自动生成并部署，当前仅供评估）：")
    _say('  restrict,command="$HOME/bin/sshhh-agent-shell" <key-type> '
         "<base64 公钥> sshhh-agent")
    return 0 if ok_all else 1


def cmd_policy(argv: list[str]) -> int:
    """查看某台主机的生效策略（管理操作）。

    修改策略仍走 hosts.toml 手编（语法见 README 策略一节）；这里是只读视图，
    免得用户为「看一眼」去解析整份清单。用免验签读取：签名失效时用户恰恰
    需要先用它检查清单被改成了什么，再决定是否 reseal（#18）。
    """
    from lib import store

    _, pos = _parse(argv, set())
    if not pos:
        raise UsageError("用法：sshhh manage policy <主机>")
    name = pos[0]
    try:
        host = store.load_unverified().get(name)
    except store.StoreError as exc:
        _warn(f"[sshhh] {exc}")
        return 3
    if host is None:
        return _unknown_host(name)

    _say(f"[{name}] {host.user}@{host.host}:{host.port}"
         + (f"  {host.description}" if host.description else ""))
    if host.allow_shell:
        _say("allow_shell = true（允许 shell 元字符；allow/deny 只对整条命令原样生效）")
    pol = host.policy
    if not pol.active:
        _say("  未配置策略：所有命令与文件通道默认放行（元字符仍默认拒绝）")
        return 0
    for key, rules in (("allow", pol.allow), ("deny", pol.deny),
                       ("allow_put", pol.allow_put), ("allow_get", pol.allow_get),
                       ("deny_put", pol.deny_put), ("deny_get", pol.deny_get)):
        if rules:
            _say(f"  {key} = ['" + "', '".join(rules) + "']")
    _say("修改请编辑 ~/.sshhh/hosts.toml 的 [hosts.<名称>.policy] 段，语法见 README")
    return 0


def cmd_reseal(argv: list[str]) -> int:
    """重新签名 hosts.toml（#18 完整性校验的合法化出口）。

    hosts.toml 现在带 HMAC 签名：程序写入自动续签，手编之后签名失效，
    所有连接在建连前被拒 —— 这是预期行为，不是故障。本命令在用户检查过
    文件内容之后重新签名。签名密钥从主密码派生，密码库未解锁时先走解锁
    流程；解锁经由窗口完成时，本进程会在拿到结果后自行再开一次密码库。
    """
    from lib import audit, protocol, store, vault

    _parse(argv, set())
    if not paths.hosts_file().exists():
        _warn("[sshhh] 还没有 hosts.toml，没有可签名的内容")
        return 3
    try:
        vault.open_vault()
    except vault.VaultError:
        status, detail = _launch("unlock", {})
        if status != "ok":
            audit.write("reseal", ok=False, error=f"密码库未解锁（{status}）")
            return _setup_failed(status, detail, "unlock")
        try:
            vault.open_vault()
        except vault.VaultError as exc:
            audit.write("reseal", ok=False, error=str(exc))
            return protocol.emit(protocol.EXIT_LOCKED, str(exc))

    try:
        store.reseal()
    except store.StoreError as exc:
        audit.write("reseal", ok=False, error=str(exc))
        _warn(f"[sshhh] {exc}")
        return 3
    audit.write("reseal")
    _say("[ok] hosts.toml 已重新签名，之后的连接会重新校验完整性")
    return 0


# --------------------------------------------------------------------------
# 密钥管理（#3 基线：生成 / 导入 / 展示；公钥部署属加固档 #15，观察名单）
# --------------------------------------------------------------------------


def _key_entry(name: str) -> str:
    """vault 里的私钥条目名（#37 预留的 key:<host> 命名空间）。"""
    return f"key:{name}"


def _key_intro(pem: str, name: str) -> None:
    """打印公钥行与指纹 —— 唯一允许出现在终端上的密钥形态。"""
    from lib import sshkeys

    comment = f"sshhh-{name}"
    _say(f"     指纹：{sshkeys.sha256_fingerprint(pem)}")
    _say(f"     公钥（放进服务器 authorized_keys 的一行）：")
    _say(f"     {sshkeys.public_key_line(pem, comment=comment)}")


def cmd_keygen(argv: list[str]) -> int:
    """生成 Ed25519 密钥对：私钥加密入 vault（key:<host>），公钥打印出来。

    私钥只在内存与密文之间流转，绝不落盘（设计宪法：明文私钥落盘 = 禁止）。
    公钥部署（写服务器 authorized_keys）属加固档写操作，当前由用户手动
    完成；`manage harden <主机> --check` 可先探测服务器端条件（#15）。
    `--force` 轮换：旧公钥不会自动从服务器移除，输出里会提醒。
    """
    from lib import audit, protocol, sshkeys, store, vault

    force = "--force" in argv
    _, pos = _parse([a for a in argv if a != "--force"], set())
    if not pos:
        raise UsageError("用法：sshhh manage keygen <主机> [--force]")
    name = pos[0]

    # 先解锁再读清单（#39）：keygen 的产出按清单里的主机身份记录
    try:
        v = vault.open_vault()
    except vault.VaultError as exc:
        return protocol.emit(protocol.EXIT_LOCKED, str(exc))

    try:
        host = store.get(name)
    except store.StoreError as exc:
        return protocol.emit(protocol.EXIT_CONFIG, str(exc))
    if host is None:
        return _unknown_host(name)

    old = v.get(_key_entry(name))
    if old and not force:
        _warn(f"[sshhh] {name} 已有密钥（{sshkeys.sha256_fingerprint(old)}）")
        _warn("[sshhh] 确认要轮换请加 --force；旧公钥需在服务器上手工移除")
        return 3

    pem = sshkeys.generate_ed25519_pem(comment=f"sshhh-{name}")
    v.set(_key_entry(name), pem)
    audit.write("key.gen", host=name, user=host.user,
                command=f"ed25519 {sshkeys.sha256_fingerprint(pem)}")
    _say(f"[ok] 已生成 Ed25519 密钥并加密存入密码库（key:{name}）")
    _key_intro(pem, name)
    _say("     部署提示：追加到服务器的 ~/.ssh/authorized_keys；Windows")
    _say("     管理员组用户是 administrators_authorized_keys（注意 ACL 只留")
    _say("     Administrators/SYSTEM）。部署后本工具会自动优先用密钥认证。")
    if old:
        _say("     注意：这是轮换出的新密钥，旧公钥记得从服务器上移除。")
    return 0


def cmd_keyimport(argv: list[str]) -> int:
    """导入已有私钥：解析校验 + 归一化后加密入 vault，全程不落盘不回显。

    文件路径省略时使用该主机遗留的 key_file 字段（#18 之后该字段不再参与
    认证，只作为迁移线索保留）。带口令的私钥拒绝导入，错误信息给出用户
    本机移除口令的办法。
    """
    from lib import audit, protocol, sshkeys, store, vault

    _, pos = _parse(argv, set())
    if not pos:
        raise UsageError("用法：sshhh manage keyimport <主机> [私钥文件]")
    name = pos[0]
    path_arg = pos[1] if len(pos) > 1 else None

    # 先解锁再读清单（#39）：key_file 线索来自清单，验签先行
    try:
        v = vault.open_vault()
    except vault.VaultError as exc:
        return protocol.emit(protocol.EXIT_LOCKED, str(exc))

    try:
        host = store.get(name)
    except store.StoreError as exc:
        return protocol.emit(protocol.EXIT_CONFIG, str(exc))
    if host is None:
        return _unknown_host(name)

    legacy = host.key_file
    if path_arg is None:
        if not legacy:
            _warn("[sshhh] 未指定私钥文件，该主机也没有遗留的 key_file 字段")
            _warn("[sshhh] 用法：sshhh manage keyimport <主机> <私钥文件>")
            return 2
        path_arg = legacy
        _say(f"[sshhh] 使用主机遗留的 key_file 路径：{path_arg}")

    source = Path(path_arg).expanduser()
    try:
        pem_raw = source.read_text(encoding="utf-8")
    except OSError as exc:
        audit.write("key.import", host=name, ok=False,
                    error=f"私钥文件读取失败：{source}")
        _warn(f"[sshhh] 读不了私钥文件 {source}：{exc}")
        return 3
    except UnicodeDecodeError:
        audit.write("key.import", host=name, ok=False,
                    error="私钥文件不是文本 PEM")
        _warn(f"[sshhh] {source} 不是文本 PEM（PuTTY 的 .ppk 请先转换导出）")
        return 3

    try:
        pem = sshkeys.normalize_pem(pem_raw)
        sshkeys.load_pkey(pem)  # 双保险：入库前确认 paramiko 能加载归一化产物
    except sshkeys.SSHKeyError as exc:
        audit.write("key.import", host=name, ok=False, error=str(exc))
        _warn(f"[sshhh] {exc}")
        return 3

    v.set(_key_entry(name), pem)

    audit.write("key.import", host=name, user=host.user,
                command=f"from {source} {sshkeys.sha256_fingerprint(pem)}")
    _say(f"[ok] 私钥已导入并加密存入密码库（key:{name}），明文不落盘")
    _key_intro(pem, name)
    if legacy:
        _say("     提示：hosts.toml 的 key_file 字段已不再参与认证，可删除")
    return 0


def cmd_keyshow(argv: list[str]) -> int:
    """显示某主机密钥的公钥行与指纹（只有公开材料会出现在输出里）。"""
    from lib import protocol, sshkeys, store, vault

    _, pos = _parse(argv, set())
    if not pos:
        raise UsageError("用法：sshhh manage keyshow <主机>")
    name = pos[0]

    # 先解锁再读清单（#39）：与其它 manage 子命令同一纪律
    try:
        v = vault.open_vault()
    except vault.VaultError as exc:
        return protocol.emit(protocol.EXIT_LOCKED, str(exc))

    try:
        host = store.get(name)
    except store.StoreError as exc:
        return protocol.emit(protocol.EXIT_CONFIG, str(exc))
    if host is None:
        return _unknown_host(name)

    pem = v.get(_key_entry(name))
    if not pem:
        _warn(f"[sshhh] {name} 还没有密钥")
        _warn(f"[sshhh] 生成：{_manual_cmd(f'manage keygen {name}')}")
        _warn(f"[sshhh] 导入：{_manual_cmd(f'manage keyimport {name} <私钥文件>')}")
        return 3
    _key_intro(pem, name)
    return 0


MANAGE_USAGE = """\
sshhh manage —— 管理操作（给用户本人执行，AI 不需要代跑）

  manage setup             只安装运行环境
  manage hosts             列出主机清单（同 list）
  manage setpass <主机>     修改某台主机的密码
  manage unlock            重新输入主密码
  manage policy <主机>      查看该主机的生效策略
  manage reseal            手编 hosts.toml 后重新签名（完整性校验，#18）
  manage keygen <主机> [--force]  生成 Ed25519 密钥（私钥入密码库，打印公钥）
  manage keyimport <主机> [文件]  导入已有私钥到密码库（省略文件用遗留 key_file）
  manage keyshow <主机>     显示该主机的公钥行与指纹
  manage audit [-n N] [--all] 查看审计记录（--all 含解密留痕）
  manage harden <主机> --check 只读探测远端可加固性（不改动，见 #15）
  manage migrate <旧目录>   从旧版 sshx 项目迁移

加主机：对 AI 说「连一下 <名称>」自动触发；或手动执行 config
（加 --here 在当前终端完成，不弹窗）。
"""


def cmd_manage(argv: list[str]) -> int:
    """管理操作入口（#25）：按受众拆分，配置 / 密码 / 审计归用户本人。"""
    if not argv:
        _say(MANAGE_USAGE)
        return 2
    sub, rest = argv[0], argv[1:]
    handler = MANAGE_COMMANDS.get(sub)
    if handler is None:
        _warn(f"未知管理子命令：{sub}")
        _say(MANAGE_USAGE)
        return 2
    return handler(rest)


COMMANDS = {
    "run": cmd_run,
    "list": cmd_list,
    "ls": cmd_list,
    "test": cmd_test,
    "put": cmd_put,
    "get": cmd_get,
    "status": cmd_status,
    # 管理层入口与旧命令别名（旧手感不破坏）
    "manage": cmd_manage,
    "config": cmd_config,
    "setpass": cmd_setpass,
    "unlock": cmd_unlock,
    "audit": cmd_audit,
    "setup": cmd_setup,
    "migrate": cmd_migrate,
    "harden": cmd_harden,
}

MANAGE_COMMANDS = {
    "setup": cmd_setup,
    "hosts": cmd_list,
    "setpass": cmd_setpass,
    "unlock": cmd_unlock,
    "policy": cmd_policy,
    "reseal": cmd_reseal,
    "keygen": cmd_keygen,
    "keyimport": cmd_keyimport,
    "keyshow": cmd_keyshow,
    "audit": cmd_audit,
    "migrate": cmd_migrate,
    "harden": cmd_harden,
}


def main(argv: list[str] | None = None) -> int:
    _setup_io()
    # SSHHH_DATA_DIR 是路径类保护的根：只在显式测试模式下生效（#18）。
    # 拒绝发生在一切数据访问之前。
    refusal = paths.override_without_test_mode()
    if refusal:
        _warn(f"[sshhh] {refusal}")
        return 3
    args = list(sys.argv[1:] if argv is None else argv)

    if not args or args[0] in ("-h", "--help", "help"):
        _say(USAGE.format(data=paths.data_dir()))
        return 0
    if args[0] in ("-V", "--version", "version"):
        _say("sshhh 2.0.0")
        return 0

    cmd, rest = args[0], args[1:]
    handler = COMMANDS.get(cmd)
    if handler is None:
        _warn(f"未知命令：{cmd}")
        _say(USAGE.format(data=paths.data_dir()))
        return 2

    try:
        # setup 只装环境，不需要 venv 里才有依赖；manage setup 同理
        if cmd != "setup" and not (cmd == "manage" and rest
                                   and rest[0] == "setup"):
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
