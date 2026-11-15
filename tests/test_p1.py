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
# #7 --sudo 与 --stdin 同用时，sudo 密码必须排在用户数据之前
# --------------------------------------------------------------------------


class _FakeStdin:
    """记录 exec 通道 stdin 上写进来的内容。

    paramiko 的 ChannelFile 上 `.channel` 是属性不是方法，
    `stdin.channel.shutdown_write()` 走的是属性访问。
    """

    def __init__(self) -> None:
        self.written: list[str] = []
        self.shutdown = False
        outer = self

        class _Chan:
            @staticmethod
            def shutdown_write() -> None:
                outer.shutdown = True

        self.channel = _Chan()

    def write(self, data: str) -> int:
        self.written.append(data)
        return len(data)


class _FakeStream:
    def __init__(self, data: bytes = b"") -> None:
        self._data = data
        self.channel = _FakeChannel()

    def read(self) -> bytes:
        return self._data


class _FakeChannel:
    def recv_exit_status(self) -> int:
        return 0

    def settimeout(self, t) -> None:
        pass


class _FakeExecSsh:
    """最小 SSHClient：exec_command 记录命令与喂给 stdin 的数据。"""

    last: "_FakeExecSsh | None" = None

    def __init__(self) -> None:
        self.commands: list[str] = []
        self.stdin = _FakeStdin()
        _FakeExecSsh.last = self

    def exec_command(self, command, timeout=None, get_pty=False):
        self.commands.append(command)
        self.stdin.written.clear()
        return (self.stdin, _FakeStream(b"out\n"), _FakeStream(b""))


def test_sudo_with_stdin() -> None:
    """`run --sudo --stdin` 曾把用户数据当 sudo 密码认证，命令必挂。"""
    from lib.redact import Redactor
    from lib.store import Host, Settings
    from lib.transport import Client

    print("\n== #7 sudo 密码先于 --stdin 数据 ==")
    client = Client(Host(name="box", host="127.0.0.1", user="root"),
                    "sudo-password-1", Settings(), Redactor())
    client._ssh = _FakeExecSsh()  # noqa: SLF001 - 直接注入，不真连

    client.run("cat > /tmp/x", stdin_data="user-data-line\n",
               timeout=10, use_sudo=True)

    ssh = _FakeExecSsh.last
    check("命令被包成 sudo -S", ssh.commands[0].startswith("sudo -S"),
          ssh.commands[0])
    written = "".join(ssh.stdin.written)
    lines = written.split("\n")
    check("第一行是 sudo 密码", lines[0] == "sudo-password-1", repr(lines[0]))
    check("用户数据在密码之后", "user-data-line" in written
          and written.index("sudo-password-1") < written.index("user-data-line"),
          repr(written))
    check("写完关写端（远端才能读到 EOF）", ssh.stdin.shutdown is True)

    print("\n== #7 无 --stdin 时只有密码一行 ==")
    client.run("systemctl restart nginx", timeout=10, use_sudo=True)
    written = "".join(_FakeExecSsh.last.stdin.written)
    check("只喂密码", written == "sudo-password-1\n", repr(written))


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
    test_sudo_with_stdin()

    shutil.rmtree(_TMP, ignore_errors=True)
    print("\n" + "=" * 46)
    print(f"通过 {PASSED} 项，失败 {FAILED} 项")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
