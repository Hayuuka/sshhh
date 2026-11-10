"""run 的输出整形：超长输出保留头尾，中间换成一行提示。

远端输出是直接进 agent 上下文的：`cat` 一个大文件、`find /`、构建日志动辄几千
行，把真正有用的信息挤出去，按 token 计费，还扩大 prompt injection 的夹带面。
靠 agent 自己记得在命令后面加 `tail -n 100` 不可靠，所以默认就有上限（#24）。

约定：
* 默认上限 50 KiB，头 60% / 尾 40%，中间换成一行 `[sshhh]` 提示
* `--tail N` 只回传最后 N 行（排障最高频的需求）
* `--max-bytes 0` 表示不限制
* 截断只影响回传给调用方的内容，审计里记下原始大小
"""

from __future__ import annotations

DEFAULT_MAX_BYTES = 50 * 1024

_HEAD_RATIO = 0.6
_TAIL_RATIO = 0.4


def _stats(text: str, **extra) -> dict:
    info = {
        "truncated": False,
        "original_bytes": len(text.encode("utf-8")),
        "kept_bytes": len(text.encode("utf-8")),
    }
    info.update(extra)
    return info


def _decode_head(data: bytes) -> str:
    """按字节切完之后解码：末尾可能是半个多字节字符，丢掉比留个乱码好。"""
    return data.decode("utf-8", "replace").rstrip("\ufffd")


def _decode_tail(data: bytes) -> str:
    return data.decode("utf-8", "replace").lstrip("\ufffd")


def shape(text: str, *, max_bytes: int = DEFAULT_MAX_BYTES,
          tail_lines: int | None = None) -> tuple[str, dict]:
    """整形输出，返回 (要回传的文本, 统计信息)。

    `tail_lines` 优先于 `max_bytes`：调用方明确要「最后 N 行」时，按行裁比按
    字节裁更符合意图。`max_bytes <= 0` 表示不限。
    """
    if not text:
        return text, _stats(text)

    if tail_lines is not None and tail_lines > 0:
        lines = text.splitlines(keepends=True)
        if len(lines) <= tail_lines:
            return text, _stats(text)
        kept = "".join(lines[-tail_lines:])
        notice = (f"[sshhh] 只回传最后 {tail_lines} 行"
                  f"（原本 {len(lines)} 行 / {len(text.encode('utf-8'))} 字节）；"
                  "需要更多请用 --tail 调整\n")
        info = _stats(text, truncated=True, kept_bytes=len((notice + kept).encode("utf-8")),
                      lines=len(lines), tail=tail_lines)
        return notice + kept, info

    if max_bytes <= 0:
        return text, _stats(text)

    data = text.encode("utf-8")
    total = len(data)
    if total <= max_bytes:
        return text, _stats(text)

    head_budget = int(max_bytes * _HEAD_RATIO)
    tail_budget = max_bytes - head_budget
    notice = (f"\n[sshhh] 输出已截断（原始 {total} 字节，只保留开头约 {head_budget} "
              f"与结尾约 {tail_budget} 字节）；需要完整内容请缩小命令范围，"
              "或用 --max-bytes / --tail 调整\n")

    head = _decode_head(data[:head_budget])
    tail = _decode_tail(data[total - tail_budget:])
    out = head + notice + tail
    info = _stats(text, truncated=True,
                  kept_bytes=len(out.encode("utf-8")), limit=max_bytes)
    return out, info
