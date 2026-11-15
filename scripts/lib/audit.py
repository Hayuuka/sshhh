"""审计日志：JSON Lines，记录谁连了哪台机器、跑了什么。

**绝不记录**密码或命令输出。写入前命令已由调用方脱敏。

「谁」也不从环境变量取：`SSHHH_CALLER` 是调用方自己填的，填什么就是什么，
把它写成 caller 字段只是制造一种「有归属」的错觉（#29）。真正可核对的是
pid / 可执行文件 / 工作目录 / 命令行前缀，见 vault._audit_open。

展示层分流（#26）：文件全保真一条不漏；`audit` 命令的默认视图隐藏
vault.open（解密留痕），`--all` 看全量。正常使用只见到业务动作，
被诱导直接解密的行为在 --all 里可查。

轮转：超过 ROTATE_BYTES 轮出一代 audit.log.1（只留一代），避免无上限增长。
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from . import paths

MAX_COMMAND_CHARS = 500

# 展示层默认隐藏的动作（文件里仍然全保真）
HIDDEN_ACTIONS = frozenset({"vault.open"})

# 单文件上限与保留代数。10 MiB 对 JSONL 来说是很宽裕的额度；
# 轮转只保留一代（audit.log.1），更老的直接丢弃。
ROTATE_BYTES = 10 * 1024 * 1024

# 倒读的扫描上限：正常日志里业务记录密度足够；极端情况（整片都是
# vault.open 且 --all 也没凑够 limit）就少显示几条，不为此读整个文件
_MAX_SCAN_BYTES = 4 * 1024 * 1024
_CHUNK = 64 * 1024


def _cut(text: str, limit: int = MAX_COMMAND_CHARS) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "…"


def write(action: str, *, host: str = "", user: str = "", command: str = "",
          exit_code: int | None = None, duration_ms: int | None = None,
          ok: bool = True, error: str = "",
          truncated: bool = False, original_bytes: int | None = None,
          auth: str = "") -> None:
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "epoch": int(time.time()),
        "action": action,
        "host": host,
        "user": user,
        "ok": ok,
    }
    if auth:
        # 本次认证方式：password / key-file（#37）。为「加固回落检测」铺路：
        # 将来受限密钥就位后，本应走密钥的连接回落到密码必须在审计里看得见。
        record["auth"] = auth
    if command:
        record["command"] = _cut(command)
    if exit_code is not None:
        record["exit"] = exit_code
    if duration_ms is not None:
        record["ms"] = duration_ms
    if error:
        record["error"] = _cut(error, 200)
    # 截断是「回给调用方的不是全部」这件事本身，必须留痕：
    # 否则事后看日志会以为命令就产出了那么点内容（#24）
    if truncated:
        record["truncated"] = True
    if original_bytes is not None:
        record["bytes"] = original_bytes

    path = paths.audit_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _rotate(path)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _rotate(path: Path) -> None:
    """超过上限把 audit.log 挪成 audit.log.1。

    两个进程同时轮转也只是各挪一次，最后留在原位的是其中一份，不会丢记录
    以外的任何东西（挪动本身是 rename，不截断内容）。
    """
    try:
        if not path.exists() or path.stat().st_size < ROTATE_BYTES:
            return
        older = Path(str(path) + ".1")
        if older.exists():
            older.unlink()
        path.replace(older)
    except OSError:
        pass


def _parse(raw: bytes) -> dict | None:
    try:
        rec = json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return None
    return rec if isinstance(rec, dict) else None


def tail(limit: int = 20, *, include_internal: bool = False) -> list[dict]:
    """取最近的审计记录，按时间正序返回。

    从文件尾部按块倒读，不再全量 read_text（#26 的性能项）。

    `include_internal=False`（展示层默认）跳过 vault.open：审计文件本身
    全保真，默认视图只显示业务动作；`--all` 传 True 看全部。
    """
    path = paths.audit_file()
    if not path.exists():
        return []

    records: list[dict] = []
    pending = b""
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            scanned = 0
            while pos > 0 and len(records) < limit and scanned < _MAX_SCAN_BYTES:
                step = min(_CHUNK, pos, _MAX_SCAN_BYTES - scanned)
                pos -= step
                scanned += step
                fh.seek(pos)
                data = fh.read(step) + pending
                pieces = data.split(b"\n")
                # pieces[0] 是跨块的半行，留给下一轮拼完整
                pending = pieces[0]
                for raw in reversed(pieces[1:]):
                    rec = _parse(raw)
                    if rec is None:
                        continue
                    if not include_internal and rec.get("action") in HIDDEN_ACTIONS:
                        continue
                    records.append(rec)
                    if len(records) >= limit:
                        break
            # 文件开头剩下的最后一行
            if len(records) < limit and pending:
                rec = _parse(pending)
                if rec is not None and (include_internal
                                        or rec.get("action") not in HIDDEN_ACTIONS):
                    records.append(rec)
    except OSError:
        return []
    records.reverse()
    return records
