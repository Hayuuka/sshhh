"""中间启动器 —— 拉起配置窗口后立刻退出。

为什么要多这一层：
    如果窗口进程的父进程是 sshhh.py 本身，那么 sshhh.py 被 agent 的命令超时
    或 taskkill /T 杀掉时，窗口会被当成子进程一起带走 —— 用户正输着主密码，
    窗口突然消失。让中间进程拉起窗口后立即退出，窗口的父进程就变成一个
    已经死掉的进程，之后杀 sshhh.py 再也带不走窗口。

用法（由 lib/console.py 调用，不面向用户）：

    python spawn_console.py <pid_file> <argv0> <argv1> ...
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

CREATE_NEW_CONSOLE = 0x00000010
CREATE_BREAKAWAY_FROM_JOB = 0x01000000
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _write_pid(path: Path, data: dict) -> None:
    try:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass


def main() -> int:
    if len(sys.argv) < 3:
        print("参数错误", file=sys.stderr)
        return 2

    pid_file = Path(sys.argv[1])
    cmd = sys.argv[2:]

    proc = None
    error = ""
    # 先试「新控制台 + 脱离作业对象」，脱离失败（作业不允许）就退回普通新控制台
    for flags in (CREATE_NEW_CONSOLE | CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_CONSOLE):
        try:
            # close_fds=True：不继承父进程的 stdin/stdout/stderr 句柄，
            # 让窗口自己打开属于它的控制台，输出才看得见、getpass 才读得到键盘。
            proc = subprocess.Popen(cmd, creationflags=flags, close_fds=True)
            break
        except OSError as exc:
            error = str(exc)
            continue

    if proc is None:
        _write_pid(pid_file, {"pid": 0, "error": error or "无法创建窗口进程"})
        return 1

    _write_pid(pid_file, {"pid": proc.pid})
    return 0


if __name__ == "__main__":
    sys.exit(main())
