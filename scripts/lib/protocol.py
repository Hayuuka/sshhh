"""agent 与脚本之间的状态协议。

约定
----
* 正常执行远端命令时，退出码就是远端命令的退出码（0-255 原样透传）。
* 当脚本**没有**执行远端命令、而是需要 agent 做决策时，返回下列保留码，
  同时向 stderr 打印一行 `SSHHH_STATUS: <NAME>`，便于精确判定。
* agent 的判定顺序：先看 stdout 是否有命令输出；若无输出且 stderr 出现
  SSHHH_STATUS，则按该状态决策。
"""

from __future__ import annotations

import sys

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
EXIT_NO_RUNTIME = 20   # 运行环境（venv/依赖）未就绪

STATUS_NAMES = {
    EXIT_CONFIGURED: "CONFIGURED",
    EXIT_CANCELLED: "CANCELLED",
    EXIT_TIMEOUT: "TIMEOUT",
    EXIT_LOCKED: "LOCKED",
    EXIT_HOST_ADDED: "HOST_ADDED",
    EXIT_NO_RUNTIME: "NO_RUNTIME",
}

STATUS_HINTS = {
    EXIT_CONFIGURED: "配置完成，直接重试原命令即可。",
    EXIT_CANCELLED: "用户取消了配置，不要再重试，把这个情况告诉用户。",
    EXIT_TIMEOUT: "配置窗口超时。告诉用户在自己的终端里执行下一条命令手动完成配置。",
    EXIT_LOCKED: "保险库无法自动解锁。告诉用户在自己的终端里执行下一条命令。",
    EXIT_HOST_ADDED: "主机已添加，直接重试原命令即可。",
    EXIT_NO_RUNTIME: "运行环境未就绪。告诉用户在自己的终端里执行下一条命令完成安装。",
}


def emit(status_code: int, message: str, hint: str = "") -> int:
    """输出状态行并返回退出码。状态行只含状态名，不含任何敏感信息。"""
    name = STATUS_NAMES.get(status_code, f"CODE_{status_code}")
    print(f"SSHHH_STATUS: {name}", file=sys.stderr)
    if message:
        print(f"SSHHH_MESSAGE: {message}", file=sys.stderr)
    advice = hint or STATUS_HINTS.get(status_code, "")
    if advice:
        print(f"SSHHH_HINT: {advice}", file=sys.stderr)
    return status_code


def is_reserved(code: int) -> bool:
    return code in STATUS_NAMES
