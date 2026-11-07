"""拉起配置窗口并等待结果。

窗口怎么开、为什么这么开，见 lib/launcher.py 的说明：交给 explorer 启动，
让窗口不在宿主的作业对象里，命令结束后依然存活。

父进程不 wait 子进程，而是轮询结果文件 + 检查窗口进程是否还活着：
  * 结果文件出现 → 读状态
  * 窗口进程消失且没有结果 → 取消（用户点了 X）
  * 等满交接时间还没结果 → 返回 pending，把窗口留给用户，自己正常退出
  * 等满硬超时 → taskkill 窗口，返回 timeout
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import launcher, paths

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_HERE = Path(__file__).resolve().parent
_CONSOLE_SCRIPT = _HERE.parent / "console_setup.py"

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

# 交接出去之后这么快就被回收，说明是宿主在清理，不是用户关窗
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

    返回 (状态, 结果详情)：ok / cancel / timeout / pending / gone / error。

    handoff：等这么久还没结果、窗口又还活着，就返回 pending 并正常退出。
    窗口本身已经不在本进程的作业对象里（见 launcher），所以即使本进程随后
    被杀，窗口和用户正在输入的内容都不受影响。
    """
    paths.ensure_data_dir()
    started = time.time()
    _reap_stale()

    gone = _check_previous()
    if gone:
        return GONE, {"elapsed": gone}

    existing = _find_live_setup()
    if existing is not None:
        result_file, pid, work = existing
        status, detail = _wait(result_file, pid, timeout, started, handoff)
        if status in (OK, CANCEL, PENDING):
            if status == PENDING:
                _write_pending(pid)
            else:
                _clear_pending()
                _cleanup_work(work)
            return status, detail
        _cleanup_work(work)
        # 那个窗口异常退出，继续走正常流程自己开一个

    if os.name != "nt":
        return _launch_inline(task, payload, timeout)

    tag = f"{os.getpid()}-{int(time.time() * 1000)}"
    work = launcher.build_work_dir(paths.data_dir(), tag)
    result_file = work / "result.json"
    pid_file = work / "pid.json"
    payload_file = work / "payload.json"
    log_file = paths.data_dir() / "console.log"

    try:
        payload_file.write_text(json.dumps(payload, ensure_ascii=False),
                                encoding="utf-8")
        cmd_file = launcher.write_cmd(
            work, sys.executable, _CONSOLE_SCRIPT, task,
            payload_file, result_file, pid_file, log_file,
            paths.data_dir(),
        )
    except OSError as exc:
        _cleanup_work(work)
        return ERROR, {"error": f"无法准备配置窗口：{exc}"}

    problem = launcher.launch(cmd_file)
    pid = 0 if problem else launcher.wait_for_pid(pid_file)
    if pid <= 0:
        detail = {
            "error": ("没能打开配置窗口"
                      + (f"（{problem}）" if problem else "，窗口没有启动")),
            "work_dir": str(work),
        }
        _cleanup_work(work)
        return ERROR, detail

    status, detail = _wait(result_file, pid, timeout, started, handoff)
    if status == ERROR:
        detail = dict(detail)
        detail["error"] = _with_stderr(str(detail.get("error", "")), work)
    if status == PENDING:
        _write_pending(pid)
    else:
        _clear_pending()
        _cleanup_work(work)
    return status, detail


def _with_stderr(message: str, work: Path) -> str:
    """把窗口的 stderr 尾巴拼进错误信息，方便一眼看出崩在哪。"""
    try:
        raw = (work / "stderr.log").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return message
    tail = raw.strip().splitlines()[-3:]
    if not tail:
        return message
    return message + "\n" + "\n".join(tail)[-400:]


def _launch_inline(task: str, payload: dict, timeout: float) -> tuple[str, dict]:
    """非 Windows：没有「新控制台」概念，退化为在当前终端里跑。"""
    work = launcher.build_work_dir(paths.data_dir(), f"{os.getpid()}-{int(time.time()*1000)}")
    result_file = work / "result.json"
    payload_file = work / "payload.json"
    payload_file.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    cmd = [sys.executable, str(_CONSOLE_SCRIPT), task, str(payload_file),
           str(result_file), str(work / "pid.json"), str(paths.data_dir())]
    try:
        proc = subprocess.Popen(cmd, stdin=None)
    except Exception as exc:
        _cleanup_work(work)
        return ERROR, {"error": f"无法启动配置窗口：{exc}"}
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc.pid)
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
        _cleanup_work(work)
        return TIMEOUT, {}

    status, detail = _read_result(result_file)
    _cleanup_work(work)
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


def _find_live_setup() -> tuple[Path, int, Path] | None:
    """找有没有别的进程已经弹了配置窗口。"""
    data_dir = paths.data_dir()
    try:
        works = sorted(data_dir.glob(".setup-*"))
    except OSError:
        return None
    for work in works:
        if not work.is_dir():
            continue
        pid = launcher.read_pid(work / "pid.json")
        if pid > 0 and _pid_alive(pid):
            return work / "result.json", pid, work
        _cleanup_work(work)
    return None


def _reap_stale() -> None:
    """清掉已经结束的窗口留下的工作目录。"""
    data_dir = paths.data_dir()
    try:
        works = list(data_dir.glob(".setup-*"))
    except OSError:
        return
    for work in works:
        if not work.is_dir():
            continue
        pid = launcher.read_pid(work / "pid.json")
        if pid <= 0 or not _pid_alive(pid):
            _cleanup_work(work)


def _cleanup_work(work: Path) -> None:
    try:
        shutil.rmtree(work, ignore_errors=True)
    except OSError:
        pass


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
    try:
        (paths.data_dir() / _PENDING_MARK).unlink()
    except OSError:
        pass


def _check_previous() -> float | None:
    """上次交接出去的窗口还在吗？

    返回它「交接后活了多少秒」仅当死得可疑（大概率被宿主清理），其余返回 None。
    """
    mark = paths.data_dir() / _PENDING_MARK
    if not mark.exists():
        return None
    try:
        data = json.loads(mark.read_text(encoding="utf-8"))
        pid = int(data.get("pid", 0))
        ts = float(data.get("ts", 0))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        _clear_pending()
        return None

    if paths.vault_file().exists():
        _clear_pending()
        return None
    if pid > 0 and _pid_alive(pid):
        return None

    lived = round(time.time() - ts, 1) if ts else 0.0
    _clear_pending()
    if lived and lived <= _KILLED_WINDOW:
        _mark_no_window(lived)
        return lived
    return None


def _mark_no_window(lived: float) -> None:
    try:
        paths.no_window_marker().write_text(
            f"检测到配置窗口在交接后 {lived} 秒被外部终止，"
            "本环境不再尝试弹窗，改用当前终端配置（config --here）。\n",
            encoding="utf-8",
        )
    except OSError:
        pass


# --------------------------------------------------------------------------
# 其它
# --------------------------------------------------------------------------


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
