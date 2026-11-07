"""配置向导 —— 在**新开的控制台窗口**里运行。

由 sshhh.py 通过 console.launch() 拉起。用户在这个窗口里输入主密码和 SSH 密码，
密码全程只存在于本进程内存，不经过命令行参数，也不会被父进程读到。

退出时把结果写进一个临时 JSON 文件，父进程读它判断成功 / 取消 / 出错。
"""

from __future__ import annotations

import getpass
import json
import os
import sys
import time
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from lib import launcher  # noqa: E402

LINE = "=" * 58
THIN = "-" * 58

# 允许通过临时文件回传给父进程的字段白名单。
# 密码、主密码、种子等任何敏感值都不得出现在这里。
RESULT_KEYS = frozenset({"status", "host", "error"})


class Cancelled(Exception):
    pass


# --------------------------------------------------------------------------
# 控制台绑定与日志
# --------------------------------------------------------------------------


def _bind_console() -> None:
    """把标准流绑到**本窗口自己的**控制台。

    窗口是隔一层启动器拉起来的，正常情况下父进程没有传句柄，标准流本来就
    指向新控制台。但如果某个宿主把句柄也继承了（stdin 是管道），getpass 会
    读不到键盘、print 会写进管道 —— 表现就是「窗口是空的，然后自己关掉」。
    这里显式打开 CONIN$/CONOUT$ 兜底，保证一定读写得到这个窗口。
    """
    if os.name != "nt":
        return
    for name in ("stdin", "stdout", "stderr"):
        stream = getattr(sys, name, None)
        try:
            if stream is not None and stream.isatty():
                continue
        except Exception:
            pass
        device = "CONIN$" if name == "stdin" else "CONOUT$"
        try:
            setattr(sys, name, open(device, "r" if name == "stdin" else "w",
                                    encoding="utf-8", errors="replace", buffering=1))
        except OSError:
            pass


def _log(msg: str) -> None:
    """写诊断日志到 ~/.sshhh/console.log。

    只记录流程与异常，不记录用户输入 —— 密码永远不会经过这里。
    """
    try:
        from lib import paths

        paths.ensure_data_dir()
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(paths.data_dir() / "console.log", "a", encoding="utf-8") as fh:
            fh.write(f"{stamp} [pid {os.getpid()}] {msg}\n")
    except Exception:
        pass


def _log_path() -> str:
    try:
        from lib import paths

        return str(paths.data_dir() / "console.log")
    except Exception:
        return "console.log"



# --------------------------------------------------------------------------
# 界面
# --------------------------------------------------------------------------


def _title(text: str) -> None:
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.kernel32.SetConsoleTitleW(text)
        except Exception:
            pass


def _banner(subtitle: str) -> None:
    print()
    print(LINE)
    print("  sshhh 配置向导")
    print(f"  {subtitle}")
    print("  密码只在这个窗口里输入，不会进入 AI 的对话上下文")
    print("  按 Ctrl+C 可随时取消")
    print(LINE)
    print()


def _section(step: str, title: str) -> None:
    print(f"[{step}] {title}")
    print(THIN)


def _ok(msg: str) -> None:
    print(f"  [ok] {msg}")


def _err(msg: str) -> None:
    print(f"  [!!] {msg}")


def _hold(seconds: int = 5) -> None:
    """停留几秒让用户看清结果，按任意键可提前关闭。"""
    print()
    end = time.time() + seconds
    while time.time() < end:
        remain = int(end - time.time()) + 1
        print(f"\r  窗口将在 {remain} 秒后关闭，按任意键立即关闭 ", end="", flush=True)
        if _kbhit():
            _getch()
            break
        time.sleep(0.2)
    print("\r" + " " * 52 + "\r", end="")


def _kbhit() -> bool:
    if os.name == "nt":
        try:
            import msvcrt

            return msvcrt.kbhit()
        except Exception:
            return False
    import select

    try:
        return bool(select.select([sys.stdin], [], [], 0)[0])
    except Exception:
        return False


def _getch() -> None:
    if os.name == "nt":
        try:
            import msvcrt

            msvcrt.getch()
        except Exception:
            pass


# --------------------------------------------------------------------------
# 输入
# --------------------------------------------------------------------------


def ask(prompt: str, default: str = "", required: bool = True) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        raw = input(f"  {prompt}{suffix}: ").strip()
        if not raw and default:
            return default
        if raw or not required:
            return raw
        _err("不能为空，请重新输入（Ctrl+C 可取消）")


def ask_secret(prompt: str, confirm: bool = False) -> str:
    while True:
        first = getpass.getpass(f"  {prompt}: ")
        if not first:
            _err("密码不能为空，请重新输入（Ctrl+C 可取消）")
            continue
        if confirm:
            again = getpass.getpass("  再输入一次: ")
            if again != first:
                _err("两次输入不一致，请重新输入")
                continue
        return first


def ask_port(prompt: str, default: str = "22") -> int:
    while True:
        raw = ask(prompt, default)
        try:
            port = int(raw)
            if 1 <= port <= 65535:
                return port
        except ValueError:
            pass
        _err("端口必须是 1-65535 之间的数字")


# --------------------------------------------------------------------------
# 任务
# --------------------------------------------------------------------------


def _import_lib():
    from lib import paths, store, vault
    from lib.lock import data_lock

    return paths, store, vault, data_lock


def do_setup(payload: dict) -> dict:
    paths, store, vault_mod, data_lock = _import_lib()

    _banner("第一次使用，需要先设置主密码和一台服务器")

    _section("1/2", "设置主密码（用来加密本地密码库）")
    print("  这个密码不会保存在任何文件里，请务必记住。")
    print("  它会被存进系统凭据管理器，之后 AI 调用时自动使用。")
    print()
    master = ask_secret("主密码", confirm=True)

    paths.ensure_data_dir()
    with data_lock(timeout=30):
        if paths.vault_file().exists():
            vault_mod.Vault.open(paths.vault_file(), master=master, allow_keyring=False)
        else:
            vault_mod.Vault.create(paths.vault_file(), master)

    if vault_mod.keyring_save(paths.vault_file(), master):
        _ok("主密码已保存到系统凭据管理器")
    else:
        _err("系统凭据管理器不可用，之后需要设置环境变量 SSHHH_MASTER 才能自动连接")

    print()
    _section("2/2", "添加一台 SSH 服务器")

    name = ask("名称（例如 prod）")
    h = ask("地址（IP 或域名）")
    u = ask("用户名", default=payload.get("default_user") or "root")
    p = ask_port("端口", default="22")
    d = ask("备注（可留空）", required=False)
    pw = ask_secret("SSH 密码")

    with data_lock(timeout=30):
        store.upsert_host(
            store.Host(name=name, host=h, user=u, port=p, description=d)
        )
        v = vault_mod.open_vault()
        v.set(name, pw)

    return {"status": "ok", "host": name}


def do_add_host(payload: dict) -> dict:
    paths, store, vault_mod, data_lock = _import_lib()

    name = payload.get("host_name") or ""
    _banner(f"添加服务器 {name}" if name else "添加一台 SSH 服务器")

    if not name:
        name = ask("名称（例如 prod）")

    # 先确保能解锁保险库，否则密码存不进去
    try:
        vault_mod.open_vault()
        _ok("密码库已解锁")
    except vault_mod.VaultError:
        print("  需要主密码才能把 SSH 密码存进密码库")
        print()
        master = ask_secret("主密码")
        vault_mod.Vault.open(paths.vault_file(), master=master, allow_keyring=False)
        if vault_mod.keyring_save(paths.vault_file(), master):
            _ok("主密码已保存到系统凭据管理器")

    print()
    _section("服务器信息", "")
    h = ask("地址（IP 或域名）")
    u = ask("用户名", default=payload.get("default_user") or "root")
    p = ask_port("端口", default="22")
    d = ask("备注（可留空）", required=False)
    pw = ask_secret("SSH 密码")

    with data_lock(timeout=30):
        store.upsert_host(
            store.Host(name=name, host=h, user=u, port=p, description=d)
        )
        v = vault_mod.open_vault()
        v.set(name, pw)

    return {"status": "ok", "host": name}


def do_unlock(payload: dict) -> dict:
    paths, store, vault_mod, data_lock = _import_lib()

    _banner("解锁密码库")
    print("  密码库无法自动解锁，请输入主密码。")
    print()

    for attempt in range(3):
        master = ask_secret("主密码")
        try:
            vault_mod.Vault.open(paths.vault_file(), master=master, allow_keyring=False)
            break
        except vault_mod.VaultError:
            _err("主密码错误")
    else:
        raise RuntimeError("主密码连续 3 次错误")

    if vault_mod.keyring_save(paths.vault_file(), master):
        _ok("已重新保存到系统凭据管理器，以后无需再输入")
    else:
        _err("系统凭据管理器不可用，之后请设置环境变量 SSHHH_MASTER")

    return {"status": "ok"}


def do_ping(payload: dict) -> dict:
    """自检用：立即返回，验证弹窗链路是否打通。"""
    return {"status": "ok"}


TASKS = {
    "setup": do_setup,
    "add_host": do_add_host,
    "unlock": do_unlock,
    "ping": do_ping,
}


# --------------------------------------------------------------------------
# 入口
# --------------------------------------------------------------------------


def _write_result(path: Path, data: dict) -> None:
    """写回传文件。

    安全约束：**只允许** status / host / error 三个字段落盘。
    其它 key 一律丢弃，防止后续维护时不小心把密码或主密码塞进来。
    """
    safe = {k: v for k, v in data.items() if k in RESULT_KEYS}
    if safe.get("status") not in ("ok", "cancel", "error"):
        safe = {"status": "error", "error": "内部结果格式错误"}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(safe, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass


def main() -> int:
    if len(sys.argv) < 5:
        print("参数错误", file=sys.stderr)
        return 2

    task = sys.argv[1]
    payload_path = Path(sys.argv[2])
    result_file = Path(sys.argv[3])
    pid_file = Path(sys.argv[4])

    # 数据目录由父进程显式传入：窗口是 explorer 拉起的，
    # 环境变量不一定还是调用方那一份，必须钉死，否则会读写到另一份密码库。
    if len(sys.argv) >= 6:
        os.environ["SSHHH_DATA_DIR"] = sys.argv[5]

    # 一次只允许一个向导实例。窗口被重复拉起时（explorer 转发、
    # 命令行被解析两次等），后到的这个立刻退出，不跟用户抢同一个控制台。
    claim = pid_file.with_name(".claimed")
    try:
        claim.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(claim, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
    except FileExistsError:
        return 0
    except OSError:
        pass

    _bind_console()

    try:
        launcher.write_pid(pid_file)
    except Exception:
        pass

    try:
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _log(f"读取参数失败：{exc}")
        _write_result(result_file, {"status": "error", "error": "参数读取失败"})
        return 2

    _log(f"启动任务 {task}（pid {os.getpid()}，父进程 {os.getppid()}）")
    _title("sshhh 配置向导")

    try:
        handler = TASKS.get(task)
        if handler is None:
            raise RuntimeError(f"未知任务：{task}")
        result = handler(payload)
    except KeyboardInterrupt:
        print()
        print(THIN)
        print("  已取消，没有做任何修改。")
        _log("用户按 Ctrl+C 取消")
        _write_result(result_file, {"status": "cancel"})
        _hold(3)
        return 0
    except Exception as exc:
        import traceback

        _log("出错：" + "".join(traceback.format_exception(exc))[-1500:])
        print()
        print(THIN)
        _err(f"出错了：{exc}")
        print(f"  详细日志：{_log_path()}")
        _write_result(result_file, {"status": "error", "error": str(exc)[:300]})
        _hold(30)
        return 1

    _write_result(result_file, result)
    _log(f"任务 {task} 完成：{result.get('status')}")

    if task == "ping":
        return 0

    print()
    print(THIN)
    if result.get("host"):
        _ok(f"已保存，AI 现在可以访问 {result['host']} 了")
    else:
        _ok("已保存")
    _hold(5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
