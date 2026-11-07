"""跨进程文件锁。

多个 agent 可能同时触发配置流程，必须串行化对 vault.enc / hosts.toml 的写入，
否则会互相覆盖。

Windows 用 msvcrt.locking，Unix 用 fcntl.flock。拿不到锁就短暂重试。
"""

from __future__ import annotations

import contextlib
import os
import time
from pathlib import Path

from . import paths


class LockTimeout(Exception):
    pass


@contextlib.contextmanager
def data_lock(timeout: float = 30.0, poll: float = 0.1):
    paths.ensure_data_dir()
    lock_path = paths.lock_file()
    fh = open(lock_path, "a+b")
    deadline = time.monotonic() + timeout
    acquired = False
    try:
        while True:
            try:
                _acquire(fh)
                acquired = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise LockTimeout(
                        "另一个 sshhh 进程正在配置，请稍后重试"
                    ) from None
                time.sleep(poll)
        yield
    finally:
        if acquired:
            try:
                _release(fh)
            except Exception:
                pass
        try:
            fh.close()
        except Exception:
            pass


def _acquire(fh) -> None:
    if os.name == "nt":
        import msvcrt

        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release(fh) -> None:
    if os.name == "nt":
        import msvcrt

        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
