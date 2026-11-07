"""拉起一个新的控制台窗口，让用户在里面输入密码。

为什么是控制台而不是 GUI：
  * 纯标准库，`CREATE_NEW_CONSOLE` 一行就能开一个新窗口；
  * 新控制台是真正的 tty，getpass 能正常隐藏输入；
  * 不依赖 tkinter（宿主嵌入的 Python 往往没有）。

父进程阻塞等待窗口结束，超时则杀掉窗口。用户直接点 X 关窗也能被正确识别为取消。
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

_CONSOLE_SCRIPT = Path(__file__).resolve().parent.parent / "console_setup.py"

OK = "ok"
CANCEL = "cancel"
TIMEOUT = "timeout"
ERROR = "error"

# 回传文件允许出现的字段（与 console_setup.RESULT_KEYS 保持一致）
_RESULT_KEYS = frozenset({"status", "host", "error"})


def available() -> bool:
    """能否弹出交互窗口。非 Windows 或没有控制台时返回 False。"""
    if os.name == "nt":
        return True
    return sys.stdin.isatty()


def launch(task: str, payload: dict, timeout: float) -> tuple[str, dict]:
    """打开配置窗口并等待结果。

    返回 (状态, 结果详情)。状态为 ok / cancel / timeout / error。
    """
    paths.ensure_data_dir()
    result_file = paths.data_dir() / f".setup-{os.getpid()}-{int(time.time() * 1000)}.json"
    try:
        result_file.unlink()
    except OSError:
        pass

    cmd = [
        sys.executable,
        str(_CONSOLE_SCRIPT),
        task,
        json.dumps(payload, ensure_ascii=False),
        str(result_file),
    ]

    kwargs: dict = {}
    if os.name == "nt":
        kwargs["creationflags"] = CREATE_NEW_CONSOLE
    else:
        # 非 Windows 没有「新控制台」概念，退化为在当前终端里跑
        kwargs["stdin"] = None

    try:
        proc = subprocess.Popen(cmd, **kwargs)
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
        result_file.unlink(missing_ok=True)
        return TIMEOUT, {}

    status, detail = _read_result(result_file)
    try:
        result_file.unlink()
    except OSError:
        pass

    if status is None:
        # 没有结果文件：用户直接关窗、或进程被中断
        return CANCEL, {}
    return status, detail


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
