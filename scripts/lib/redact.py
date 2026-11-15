"""输出脱敏：远端可能把密码回显出来，转发前一律替换掉。"""

from __future__ import annotations

import re
from urllib.parse import quote

PLACEHOLDER = "[REDACTED]"

_GENERIC = [
    # `pwd` 不进来：它是「打印工作目录」的极常见写法（Makefile、CI 输出、
    # shell 提示符），误伤会把排障要看的路径抹掉（#11）。
    re.compile(r"(?i)((?:password|passwd)\s*[=:]\s*)(\S+)"),
    re.compile(r"(?i)(--password[= ])(\S+)"),
]


class Redactor:
    def __init__(self, secrets: list[str] | None = None):
        self._values: list[str] = []
        for s in secrets or []:
            self.add(s)

    def add(self, secret: str | None) -> None:
        if not secret or len(secret) < 4:
            return
        variants = {
            secret,
            quote(secret, safe=""),
            secret.replace("\\", "\\\\"),
            '"' + secret + '"',
            "'" + secret + "'",
        }
        for v in sorted(variants, key=len, reverse=True):
            if v and v not in self._values:
                self._values.append(v)

    def clean(self, text: str) -> str:
        if not text:
            return text
        for v in self._values:
            if v in text:
                text = text.replace(v, PLACEHOLDER)
        for pat in _GENERIC:
            text = pat.sub(lambda m: m.group(1) + PLACEHOLDER, text)
        return text

    def __bool__(self) -> bool:
        return bool(self._values)
