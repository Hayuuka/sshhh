"""审计日志：JSON Lines，记录谁连了哪台机器、跑了什么。

**绝不记录**密码或命令输出。写入前命令已由调用方脱敏。

「谁」也不从环境变量取：`SSHHH_CALLER` 是调用方自己填的，填什么就是什么，
把它写成 caller 字段只是制造一种「有归属」的错觉（#29）。真正可核对的是
pid / 可执行文件 / 工作目录 / 命令行前缀，见 vault._audit_open。
"""

from __future__ import annotations

import json
import time

from . import paths

MAX_COMMAND_CHARS = 500


def _cut(text: str, limit: int = MAX_COMMAND_CHARS) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "…"


def write(action: str, *, host: str = "", user: str = "", command: str = "",
          exit_code: int | None = None, duration_ms: int | None = None,
          ok: bool = True, error: str = "") -> None:
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "epoch": int(time.time()),
        "action": action,
        "host": host,
        "user": user,
        "ok": ok,
    }
    if command:
        record["command"] = _cut(command)
    if exit_code is not None:
        record["exit"] = exit_code
    if duration_ms is not None:
        record["ms"] = duration_ms
    if error:
        record["error"] = _cut(error, 200)

    path = paths.audit_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def tail(limit: int = 20) -> list[dict]:
    path = paths.audit_file()
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out: list[dict] = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
