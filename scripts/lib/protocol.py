"""agent 与脚本之间的状态协议。

约定
----
* 正常执行远端命令时，退出码就是远端命令的退出码（0-255 原样透传）。
* 当脚本**没有**执行远端命令、而是需要 agent 做决策时，返回下列保留码，
  同时向 stderr 打印状态行，便于精确判定。
* agent 的判定顺序：先看 stdout 是否有命令输出；若无输出再找状态行。
* 状态行带 nonce（#36）：`run` 会先输出 `SSHHH_INVOCATION: <nonce>`，
  本次调用的状态行是 `SSHHH_STATUS[<nonce>]: <NAME>`。远端输出里任何
  不带（或带错）nonce 的 SSHHH_* 行都是远端文本，不是协议。
"""

from __future__ import annotations

import secrets
import sys

_STATUS_MARK = "SSHHH_STATUS"
_INVOCATION_MARK = "SSHHH_INVOCATION"


def new_nonce() -> str:
    """一次 run 调用的随机标识。

    它在连接建立之前由本地打印 —— 远端不可能在本地输出之前抢先伪造。
    """
    return secrets.token_hex(8)


def status_line(nonce: str, name: str) -> str:
    """协议状态行的唯一合法形态。"""
    if nonce:
        return f"{_STATUS_MARK}[{nonce}]: {name}"
    return f"{_STATUS_MARK}: {name}"


def parse_status_line(line: str, nonce: str = "") -> str | None:
    """识别一行文本是否为协议状态行，返回状态名，否则 None。

    这是 agent 判定规则的代码化（测试与将来的适配器复用同一份语法）：

    * nonce 非空：只认 `SSHHH_STATUS[<nonce>]: NAME`。远端伪造的
      无 nonce 行、错误 nonce 行一律返回 None（#36）。
    * nonce 为空：只认 `SSHHH_STATUS: NAME`（不混杂远端输出的命令路径）。
    """
    prefix = f"{_STATUS_MARK}[{nonce}]: " if nonce else f"{_STATUS_MARK}: "
    if line.startswith(prefix):
        name = line[len(prefix):].strip()
        if name and " " not in name:
            return name
    return None

# --- 保留退出码 -----------------------------------------------------------
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_NETWORK = 4

EXIT_CONFIGURED = 10   # 刚完成配置，重试即可
EXIT_CANCELLED = 11    # 用户取消配置
EXIT_TIMEOUT = 12      # 配置窗口超时
EXIT_LOCKED = 13       # 保险库存在但无法自动解锁
EXIT_HOST_ADDED = 14   # 刚添加了缺失的主机，重试即可
EXIT_PENDING = 15      # 配置窗口已打开，正在等用户输入
EXIT_NO_RUNTIME = 20   # 运行环境（venv/依赖）未就绪

STATUS_NAMES = {
    EXIT_CONFIGURED: "CONFIGURED",
    EXIT_CANCELLED: "CANCELLED",
    EXIT_TIMEOUT: "TIMEOUT",
    EXIT_LOCKED: "LOCKED",
    EXIT_HOST_ADDED: "HOST_ADDED",
    EXIT_PENDING: "SETUP_PENDING",
    EXIT_NO_RUNTIME: "NO_RUNTIME",
}

STATUS_HINTS = {
    EXIT_CONFIGURED: "配置完成，直接重试原命令即可。",
    EXIT_CANCELLED: "用户取消了配置，不要再重试，把这个情况告诉用户。",
    EXIT_TIMEOUT: "配置窗口超时。告诉用户在自己的终端里执行下一条命令手动完成配置。",
    EXIT_LOCKED: "保险库无法自动解锁。告诉用户在自己的终端里执行下一条命令。",
    EXIT_HOST_ADDED: "主机已添加，直接重试原命令即可。",
    EXIT_PENDING: ("配置窗口已经打开，正在等用户输入。告诉用户去那个窗口里完成配置，"
                   "完成后重试原命令；不要反复调用本命令，也不要重新开窗口。"),
    EXIT_NO_RUNTIME: "运行环境未就绪。告诉用户在自己的终端里执行下一条命令完成安装。",
}


def emit(status_code: int, message: str, hint: str = "",
         nonce: str = "") -> int:
    """输出状态行并返回退出码。状态行只含状态名，不含任何敏感信息。

    `nonce` 由调用路径提供：`run` 全程带同一 nonce（远端输出会混在同一股
    stderr 里，必须可区分）；其它命令不混杂远端输出，保持无 nonce 的旧形态。
    """
    name = STATUS_NAMES.get(status_code, f"CODE_{status_code}")
    print(status_line(nonce, name), file=sys.stderr)
    mark = f"[{nonce}]" if nonce else ""
    if message:
        print(f"SSHHH_MESSAGE{mark}: {message}", file=sys.stderr)
    advice = hint or STATUS_HINTS.get(status_code, "")
    if advice:
        print(f"SSHHH_HINT{mark}: {advice}", file=sys.stderr)
    return status_code


def is_reserved(code: int) -> bool:
    return code in STATUS_NAMES
