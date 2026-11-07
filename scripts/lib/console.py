"""拉起一个新的控制台窗口，让用户在里面输入密码。

为什么是控制台而不是 GUI：
  * 纯标准库，`CREATE_NEW_CONSOLE` 一行就能开一个新窗口；
  * 新控制台是真正的 tty，getpass 能正常隐藏输入；
  * 不依赖 tkinter（宿主嵌入的 Python 往往没有）。

为什么窗口要「隔一层」启动：
  直接 Popen 的话，窗口是 sshhh.py 的子进程。agent 的命令超时、或者外部
  taskkill /T，会把窗口一起杀掉——用户正输入主密码，窗口突然消失。
  所以先起一个 spawn_console.py 中间进程，它拉起窗口后立刻退出，窗口的
  父进程随即变成一个已结束的进程，之后杀 sshhh.py 带不走它。

父进程不再 wait 子进程，而是轮询结果文件 + 检查窗口进程是否还活着：
  * 结果文件出现 → 读状态
  * 窗口进程消失且没有结果 → 取消（用户点了 X）
  * 到时间还没结果 → taskkill 窗口，返回 timeout
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from . import paths

CREATE_NEW_CONSOLE = 0x00000010
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_HERE = Path(__file__).resolve().parent
_CONSOLE_SCRIPT = _HERE.parent / "console_setup.py"
_SPAWN_SCRIPT = _HERE.parent / "spawn_console.py"

OK = "ok"
CANCEL = "cancel"
TIMEOUT = "timeout"
PENDING = "pending"
GONE = "gone"
ERROR = "error"

# 回传文件允许出现的字段（与 console_setup.RESULT_KEYS 保持一致）
_RESULT_KEYS = frozenset({"status", "host", "error"})

# 窗口启动后这么快就退出，基本可以判定为启动失败而不是用户关窗
_FAST_EXIT = 3.0

# 交接出去之后这么快就被杀掉，说明是宿主在回收进程，不是用户关窗
_KILLED_WINDOW = 15.0

_PENDING_MARK = ".pending"


def available() -> bool:
    """能否弹出交互窗口。非 Windows 或没有控制台时返回 False。"""
    if paths.no_window_marker().exists():
        return False
    if os.name == "nt":
        return True
    return sys.stdin.isatty()


def launch(task: str, payload: dict, timeout: float,
           handoff: float | None = None) -> tuple[str, dict]:
    """打开配置窗口并等待结果。

    返回 (状态, 结果详情)。状态为 ok / cancel / timeout / pending / gone / error。

    handoff：等这么久还没结果、而窗口还活着，就返回 pending 并正常退出，
    把窗口交给用户 —— 正常退出时窗口不会被本进程带走。

    下一次调用会检查上次交出去的窗口还在不在：如果已经没了、配置又没完成，
    说明这个宿主会在命令结束时回收残留进程，那就标记 .no-window，
    之后不再弹窗，直接让用户在自己终端里配置。
    """
    paths.ensure_data_dir()
    started = time.time()
    _reap_stale()

    gone = _check_previous()
    if gone:
        return GONE, {"elapsed": gone}

    # 已经有一个窗口在等用户输入？直接等它，避免弹第二个窗口
    existing = _find_live_setup()
    if existing is not None:
        result_file, pid = existing
        status, detail = _wait(result_file, pid, timeout, started, handoff)
        if status in (OK, CANCEL, PENDING):
            if status == PENDING:
                _write_pending(pid)
            else:
                _clear_pending()
            return status, detail
        # 那个窗口异常退出，继续走正常流程自己开一个

    tag = f"{os.getpid()}-{int(time.time() * 1000)}"
    result_file = paths.data_dir() / f".setup-{tag}.json"
    pid_file = paths.data_dir() / f".setup-{tag}.pid"
    _unlink(result_file, pid_file)

    if os.name != "nt":
        return _launch_inline(task, payload, result_file, timeout)

    cmd = [
        sys.executable,
        str(_SPAWN_SCRIPT),
        str(pid_file),
        sys.executable,
        str(_CONSOLE_SCRIPT),
        task,
        json.dumps(payload, ensure_ascii=False),
        str(result_file),
    ]
    try:
        # 中间进程只活几十毫秒，别让它闪一个黑框
        subprocess.run(cmd, timeout=20, creationflags=_NO_WINDOW,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as exc:
        _unlink(result_file, pid_file)
        return ERROR, {"error": f"无法启动配置窗口：{exc}"}

    pid, spawn_error = _read_pid(pid_file)
    if pid <= 0:
        _unlink(result_file, pid_file)
        return ERROR, {"error": f"无法启动配置窗口：{spawn_error or '未知原因'}"}

    status, detail = _wait(result_file, pid, timeout, started, handoff)
    if status == PENDING:
        _write_pending(pid)
    else:
        _clear_pending()
        _unlink(result_file, pid_file)
    return status, detail


# --------------------------------------------------------------------------
# 交接标记
# --------------------------------------------------------------------------


def _write_pending(pid: int) -> None:
    mark = paths.data_dir() / _PENDING_MARK
    try:
        mark.write_text(json.dumps({"pid": pid, "ts": time.time()}), encoding="utf-8")
    except OSError:
        pass


def _clear_pending() -> None:
    _unlink(paths.data_dir() / _PENDING_MARK)


def _check_previous() -> float | None:
    """上次交接出去的窗口还在吗？

    返回窗口「交接后活了多少秒」仅当它死得可疑（大概率被宿主回收），
    其余情况返回 None。
    """
    mark = paths.data_dir() / _PENDING_MARK
    if not mark.exists():
        return None
    try:
        data = json.loads(mark.read_text(encoding="utf-8"))
        pid = int(data.get("pid", 0))
        ts = float(data.get("ts", 0))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        _unlink(mark)
        return None

    if paths.vault_file().exists():
        _unlink(mark)
        return None
    if pid > 0 and _pid_alive(pid):
        # 窗口还开着，交给 _find_live_setup 继续等
        return None

    lived = round(time.time() - ts, 1) if ts else 0.0
    _unlink(mark)
    _reap_stale()
    if lived and lived <= _KILLED_WINDOW:
        # 交接后十来秒就被清掉，用户不可能这么快输完：是宿主在回收进程
        _mark_no_window(lived)
        return lived
    return None


def _reap_stale() -> None:
    """清掉已经结束的窗口留下的 pid / 结果文件。"""
    try:
        stale = list(paths.data_dir().glob(".setup-*.pid"))
    except OSError:
        return
    for pid_file in stale:
        pid, _ = _read_pid(pid_file)
        if pid <= 0 or not _pid_alive(pid):
            _unlink(pid_file, pid_file.with_suffix(".json"))


def _mark_no_window(lived: float) -> None:
    try:
        paths.no_window_marker().write_text(
            f"检测到配置窗口在交接后 {lived} 秒被外部终止，"
            "本环境不再尝试弹窗，改用当前终端配置（config --here）。\n",
            encoding="utf-8",
        )
    except OSError:
        pass


def _launch_inline(task: str, payload: dict, result_file: Path,
                   timeout: float) -> tuple[str, dict]:
    """非 Windows：没有「新控制台」概念，退化为在当前终端里跑。"""
    cmd = [
        sys.executable, str(_CONSOLE_SCRIPT), task,
        json.dumps(payload, ensure_ascii=False), str(result_file),
    ]
    try:
        proc = subprocess.Popen(cmd, stdin=None)
    except Exception as exc:
        return ERROR, {"error": f"无法启动配置窗口：{exc}"}
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc.pid)
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
        _unlink(result_file)
        return TIMEOUT, {}

    status, detail = _read_result(result_file)
    _unlink(result_file)
    if status is None:
        return CANCEL, {}
    return status, detail


# --------------------------------------------------------------------------
# 等待与进程状态
# --------------------------------------------------------------------------


def _wait(result_file: Path, pid: int, timeout: float, started: float,
          handoff: float | None = None) -> tuple[str, dict]:
    """轮询结果文件，同时盯着窗口进程是否还活着。"""
    deadline = started + timeout
    handoff_at = started + handoff if handoff is not None else None
    while True:
        status, detail = _read_result(result_file)
        if status is not None:
            return status, detail

        if not _pid_alive(pid):
            # 进程已退出，给结果文件一点落盘时间
            time.sleep(0.3)
            status, detail = _read_result(result_file)
            if status is not None:
                return status, detail
            elapsed = round(time.time() - started, 1)
            if elapsed <= _FAST_EXIT:
                return ERROR, {
                    "error": (f"配置窗口启动后 {elapsed} 秒就退出了，没有返回任何结果。"
                              f"详细日志见 {paths.data_dir() / 'console.log'}"),
                    "elapsed": elapsed,
                }
            return CANCEL, {"elapsed": elapsed}

        now = time.time()
        if handoff_at is not None and now >= handoff_at:
            # 窗口还开着、用户还在输：正常退出把窗口交出去，
            # 这样即使本进程随后被外部杀掉，也不会连带杀掉窗口。
            return PENDING, {"elapsed": round(now - started, 1)}

        if now >= deadline:
            _kill_tree(pid)
            time.sleep(0.2)
            status, detail = _read_result(result_file)
            if status is not None:
                return status, detail
            return TIMEOUT, {}

        time.sleep(0.15)


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes

            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            handle = k32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
            if not handle:
                return False
            try:
                return k32.WaitForSingleObject(handle, 0) == 0x00000102  # WAIT_TIMEOUT
            finally:
                k32.CloseHandle(handle)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _find_live_setup() -> tuple[Path, int] | None:
    """找有没有别的进程已经弹了配置窗口。"""
    try:
        candidates = sorted(paths.data_dir().glob(".setup-*.pid"))
    except OSError:
        return None
    for pid_file in candidates:
        pid, _ = _read_pid(pid_file)
        if pid > 0 and _pid_alive(pid):
            result_file = pid_file.with_suffix(".json")
            return result_file, pid
        # 残留的旧文件，顺手清掉
        _unlink(pid_file, pid_file.with_suffix(".json"))
    return None


def _read_pid(path: Path) -> tuple[int, str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return int(raw.get("pid", 0)), str(raw.get("error", ""))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return 0, ""


def _read_result(path: Path) -> tuple[str | None, dict]:
    """读取回传结果。

    与 console_setup._write_result 使用同一份字段白名单做双向校验：
    即使将来有人往结果文件里塞了敏感字段，这里也会直接丢弃。
    """
    if not path.exists():
        return None, {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, {}
    if not isinstance(raw, dict):
        return None, {}
    data = {k: v for k, v in raw.items() if k in _RESULT_KEYS}
    status = str(data.get("status", "")).lower()
    if status not in (OK, CANCEL, ERROR):
        return None, {}
    return status, data


def _unlink(*paths_: Path) -> None:
    for p in paths_:
        try:
            p.unlink()
        except OSError:
            pass


def _kill_tree(pid: int) -> None:
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True, timeout=15, creationflags=_NO_WINDOW,
            )
            return
        except Exception:
            pass
    try:
        os.kill(pid, 9)
    except Exception:
        pass
