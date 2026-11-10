"""落盘小工具。

`hosts.toml` / `known_hosts` / `vault.enc` 这类「一次写坏就等于整份不可用」的
文件，必须 tmp + `os.replace` 原子替换：直接 `write_text` 的窗口期里，并发读
会拿到截断的内容，表现为「清单解析失败」「指纹库损坏」。

调用方仍需自行持有 `data_lock`（跨进程串行化写），本模块只保证单次替换的
原子性，不负责互斥。
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

# Windows 上目标文件正被别的进程打开时 os.replace 会报 PermissionError
# （共享冲突）。读取方通常只是瞬间看一眼，重试几次即可，不必让调用方处理。
_REPLACE_RETRIES = 8
_REPLACE_DELAY = 0.05

# 读侧的重试（同上，Windows 共享冲突）
_READ_RETRIES = 8
_READ_DELAY = 0.03


def atomic_write_text(path: Path, text: str, *, mode: int = 0o600) -> None:
    """原子地把 `text` 写到 `path`。

    同目录建临时文件再 replace：跨设备会退化，同目录不会。失败时清掉临时文件，
    不留下半成品。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        _replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _replace(tmp: Path, path: Path) -> None:
    for attempt in range(_REPLACE_RETRIES):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == _REPLACE_RETRIES - 1:
                raise
            time.sleep(_REPLACE_DELAY)


def read_text(path: Path, *, encoding: str = "utf-8",
              retries: int = _READ_RETRIES, delay: float = _READ_DELAY) -> str:
    """读文本，遇到 Windows 上的瞬时共享冲突就重试几次。

    原子替换（MoveFileEx）执行的那一瞬间，另一个进程 `open()` 同一路径可能
    拿到 PermissionError：这是 Windows 的共享模式所致，不是文件真的坏了。
    直接把这种错误抛给调用方，就会出现「并发时有概率报 hosts.toml 读取失败」，
    和 #9 想消灭的现象没区别。
    """
    last: OSError | None = None
    for attempt in range(max(1, retries)):
        try:
            return path.read_text(encoding=encoding)
        except PermissionError as exc:      # 典型的共享冲突
            last = exc
            time.sleep(delay)
        except OSError as exc:
            last = exc
            # 文件不存在之类的错误没有重试意义
            if isinstance(exc, FileNotFoundError):
                raise
            time.sleep(delay)
    raise last if last is not None else OSError(f"读取失败：{path}")
