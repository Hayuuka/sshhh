"""跨进程文件锁。

多个 agent 可能同时触发配置流程，必须串行化对 vault.enc / hosts.toml 的写入，
否则会互相覆盖。

Windows 用 msvcrt.locking，Unix 用 fcntl.flock。拿不到锁就短暂重试。

**可重入**：同一线程里嵌套调用不会再抢一次文件锁。这一点是必需的 ——
写函数把锁下沉到自己内部（#9）之后，外层调用方（console_setup / migrate）
再包一层 `with data_lock()` 就会自己等自己：flock 与 msvcrt 的锁都挂在文件
描述符上，同一个进程开第二个句柄同样拿不到。

注意可重入是**按线程**算的，不是按进程：同一进程的两个线程同时进 data_lock
仍会互斥（第二个线程会等到超时），所以别在线程池里写数据目录。
"""

from __future__ import annotations

import contextlib
import os
import threading
import time
from pathlib import Path

from . import paths


class LockTimeout(Exception):
    pass


_STATE = threading.local()


def _depth() -> int:
    return getattr(_STATE, "depth", 0)


@contextlib.contextmanager
def data_lock(timeout: float = 30.0, poll: float = 0.1):
    depth = _depth()
    if depth:
        _STATE.depth = depth + 1
        try:
            yield
        finally:
            _STATE.depth = depth
        return

    with _file_lock(paths.lock_file(), timeout, poll):
        _STATE.depth = 1
        try:
            yield
        finally:
            _STATE.depth = 0


@contextlib.contextmanager
def bootstrap_lock(timeout: float = 300.0, poll: float = 0.2):
    """运行环境自举的独占锁（#10）。

    两个 agent 同时首跑时，后到的那个必须等前一个把 venv 建完，而不是也进
    `_create_venv`（那里开头会 rmtree，会把另一个正在 pip install 的目录删掉）。
    故意与 data_lock 用不同的锁文件：装依赖要几分钟，不该堵塞读写操作。
    """
    paths.ensure_data_dir()
    with _file_lock(paths.bootstrap_lock_file(), timeout, poll):
        yield


@contextlib.contextmanager
def _file_lock(lock_path: Path, timeout: float, poll: float):
    fh = _open_retry(lock_path, timeout, poll)
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


def _open_retry(lock_path: Path, timeout: float, poll: float):
    """打开锁文件；Windows 上刚创建的文件偶尔会短暂占住，退避重试。

    并发首跑时几个进程同时创建/打开 `.bootstrap`，实测偶发 PermissionError。
    打不开锁文件导致整个 ensure() 崩掉，比晚 100 毫秒拿到锁糟糕得多。
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            return open(lock_path, "a+b")
        except PermissionError:
            if time.monotonic() >= deadline:
                raise LockTimeout(
                    f"打不开锁文件（{lock_path}），可能有别的进程正占用，请稍后重试"
                ) from None
            time.sleep(poll)


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
