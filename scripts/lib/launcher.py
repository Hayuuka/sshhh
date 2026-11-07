"""把配置窗口「洗」出宿主的作业对象。

为什么需要这一层
----------------
如果窗口是本进程的子进程，宿主（把每条命令放进 job object、命令结束就回收
残留进程的环境）会在命令结束时把窗口一起杀掉 —— 用户正输着密码，窗口消失。

实测结论（Windows）：
  * 直接 Popen(creationflags=CREATE_NEW_CONSOLE)：子进程仍在 job 里，
    CREATE_BREAKAWAY_FROM_JOB 也逃不掉（job 不允许 breakaway）
  * 交给 explorer.exe 启动：进程归属于 explorer，**不在 job 里**，
    命令结束后依然存活

所以做法是：写一个 .cmd，交给 explorer.exe 打开。窗口是 explorer 的子进程，
关掉 sshhh.py 带不走它。

编码注意：.cmd 必须用系统 ANSI（mbcs）写，不能用 UTF-8 —— cmd.exe 按当前
代码页逐行解析批处理，UTF-8 的中文路径会被解析坏。
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

_EXPLORER = Path(os.environ.get("WINDIR", r"C:\Windows")) / "explorer.exe"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def build_work_dir(base: Path, tag: str) -> Path:
    work = base / f".setup-{tag}"
    work.mkdir(parents=True, exist_ok=True)
    return work


def write_cmd(work: Path, python: str, script: Path, task: str,
              payload_file: Path, result_file: Path, pid_file: Path,
              log_file: Path, data_dir: Path) -> Path:
    """写启动脚本。只用 ASCII 字面量，路径原样带引号。

    stderr 重定向到单独的文件：cmd 的 `2>>` 会独占句柄，
    如果和窗口自己写的日志用同一个文件，python 里写日志会 PermissionError。
    """
    cmd_file = work / "run.cmd"
    err_file = work / "stderr.log"
    work.mkdir(parents=True, exist_ok=True)
    lines = [
        "@echo off",
        "title sshhh setup",
        f'"{python}" "{script}" "{task}" "{payload_file}" '
        f'"{result_file}" "{pid_file}" "{data_dir}" 2>>"{err_file}"',
    ]
    text = "\r\n".join(lines) + "\r\n"
    # mbcs = 系统 ANSI，cmd.exe 才能正确解析中文路径
    try:
        cmd_file.write_bytes(text.encode("mbcs", "replace"))
    except LookupError:
        cmd_file.write_bytes(text.encode("gbk", "replace"))
    return cmd_file


def launch(cmd_file: Path) -> str:
    """交给 explorer 打开，返回错误描述（空字符串表示已发出请求）。"""
    if not _EXPLORER.exists():
        return "找不到 explorer.exe"
    try:
        subprocess.run([str(_EXPLORER), str(cmd_file)], timeout=15,
                       creationflags=_NO_WINDOW,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return ""
    except Exception as exc:  # noqa: BLE001
        return str(exc)


def wait_for_pid(pid_file: Path, timeout: float = 8.0) -> int:
    """等窗口自己把 pid 写出来。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        pid = read_pid(pid_file)
        if pid > 0:
            return pid
        time.sleep(0.1)
    return 0


def read_pid(pid_file: Path) -> int:
    try:
        return int(json.loads(pid_file.read_text(encoding="utf-8")).get("pid", 0))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return 0


def write_pid(pid_file: Path) -> None:
    """由窗口进程自己调用，供父进程识别与终止。"""
    try:
        pid_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = pid_file.with_suffix(".tmp")
        tmp.write_text(json.dumps({"pid": os.getpid()}), encoding="utf-8")
        os.replace(tmp, pid_file)
    except OSError:
        pass
