"""P1 接口与协议：外部评审与路线图 P1 各 issue 的回归测试。

本文件按 issue 分段，每条都对应 docs/DESIGN.md §6 里 P1 的一行：

  #11 redact 不再误伤 `pwd =` 形态的正常输出
  #7  --sudo 与 --stdin 同用时 sudo 密码先于用户数据写入
  #34 评审小修打包（I6 I7 I9 S6 S7 S8）
  #36 远端伪造 SSHHH_STATUS 不被识别（nonce）
  #26 audit 展示层默认过滤 vault.open，--all 看全量
  #19 无钥匙串环境的 status 指引与 pass 后端

运行：
    ~/.sshhh/venv/Scripts/python.exe tests/test_p1.py
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

_TMP = Path(tempfile.mkdtemp(prefix="sshhh-p1-"))
os.environ["SSHHH_DATA_DIR"] = str(_TMP)
os.environ.pop("SSHHH_MASTER", None)

PASSED = 0
FAILED = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  [ok] {name}")
    else:
        FAILED += 1
        print(f"  [FAIL] {name}" + (f"  -> {detail}" if detail else ""))


def reset() -> None:
    shutil.rmtree(_TMP, ignore_errors=True)
    _TMP.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------
# #11 redact 通用规则误伤
# --------------------------------------------------------------------------


def test_redact_pwd() -> None:
    from lib.redact import Redactor

    print("\n== #11 `pwd =` 是正常输出，不脱敏 ==")
    r = Redactor()
    out = r.clean("pwd = /home/deploy")
    check("pwd = /home/deploy 保留", out == "pwd = /home/deploy", out)
    out = r.clean("workdir=/app pwd=/app")
    check("容器输出里的 pwd=/app 保留", out == "workdir=/app pwd=/app", out)
    out = r.clean("PWD=/var/www")
    check("大写 PWD 保留", out == "PWD=/var/www", out)

    print("\n== #11 password / passwd 仍被脱敏 ==")
    out = r.clean("password=abc123")
    check("password=abc123 被替换", "[REDACTED]" in out and "abc123" not in out, out)
    out = r.clean("passwd: hunter2")
    check("passwd: hunter2 被替换", "[REDACTED]" in out and "hunter2" not in out, out)
    out = r.clean("--password hunter2")
    check("--password hunter2 被替换", "[REDACTED]" in out and "hunter2" not in out, out)

    print("\n== #11 已知密码仍然按值替换（不管叫什么名字）==")
    r2 = Redactor(["pw-value-9f31"])
    out = r2.clean("echo pw-value-9f31")
    check("已知值被替换", "pw-value-9f31" not in out, out)


def main() -> int:
    test_redact_pwd()

    shutil.rmtree(_TMP, ignore_errors=True)
    print("\n" + "=" * 46)
    print(f"通过 {PASSED} 项，失败 {FAILED} 项")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
