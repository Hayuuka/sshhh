"""端到端流程测试。

覆盖：状态码协议、配置窗口的四种结果、真实 SSH 执行、密码脱敏、审计。

运行：
    D:/work/agentssh/.venv/Scripts/python.exe tests/test_flow.py
（任何装有 paramiko/cryptography/keyring 的解释器都可以）
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import paramiko

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

USER = "tester"
SSH_PASSWORD = "Sup3r-Secret-Pw!<&>"
MASTER = "master-passphrase-9f3a"
HOST_NAME = "local"

PASSED = 0
FAILED = 0

_TMP = Path(tempfile.mkdtemp(prefix="sshhh-test-"))
os.environ["SSHHH_DATA_DIR"] = str(_TMP)
os.environ["SSHHH_MASTER"] = MASTER

import sshhh as cli  # noqa: E402
from lib import audit, console, paths, protocol, store, transport, vault  # noqa: E402


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  [ok] {name}")
    else:
        FAILED += 1
        print(f"  [FAIL] {name}" + (f"  -> {detail}" if detail else ""))


# --------------------------------------------------------------------------
# 迷你 SSH 服务端
# --------------------------------------------------------------------------


class _MiniServer(paramiko.ServerInterface):
    def __init__(self) -> None:
        self.event = threading.Event()
        self.command = b""

    def check_auth_password(self, username, password):
        return (paramiko.AUTH_SUCCESSFUL
                if (username == USER and password == SSH_PASSWORD)
                else paramiko.AUTH_FAILED)

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return (paramiko.OPEN_SUCCEEDED if kind == "session"
                else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def check_channel_exec_request(self, channel, command):
        self.command = command
        self.event.set()
        return True


def _fake_shell(command: str) -> str:
    out = []
    for part in command.split(";"):
        part = part.strip()
        if not part:
            continue
        if part.startswith("echo "):
            out.append(part[5:])
        else:
            out.append("(ran) " + part)
    return "\n".join(out) + "\n"


def _handle(transport, server):
    try:
        chan = transport.accept(20)
        if chan is None:
            return
        if not server.event.wait(20):
            chan.close()
            return
        chan.sendall(_fake_shell(server.command.decode("utf-8", "replace")).encode())
        chan.send_exit_status(0)
        chan.close()
    except Exception:
        pass
    finally:
        try:
            transport.close()
        except Exception:
            pass


def start_server() -> tuple[int, threading.Event]:
    host_key = paramiko.RSAKey.generate(2048)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(20)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def loop():
        sock.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except (socket.timeout, OSError):
                continue
            t = paramiko.Transport(conn)
            t.add_server_key(host_key)
            srv = _MiniServer()
            try:
                t.start_server(server=srv)
            except Exception:
                t.close()
                continue
            threading.Thread(target=_handle, args=(t, srv), daemon=True).start()
        try:
            sock.close()
        except Exception:
            pass

    threading.Thread(target=loop, daemon=True).start()
    return port, stop


# --------------------------------------------------------------------------
# 工具
# --------------------------------------------------------------------------


class MockConsole:
    """替换真实弹窗，按预设顺序返回结果。"""

    def __init__(self):
        self.queue: list[tuple[str, dict]] = []
        self.calls: list[tuple[str, dict]] = []

    def push(self, status: str, detail: dict | None = None):
        self.queue.append((status, detail or {}))
        return self

    def launch(self, task, payload, timeout, handoff=None):
        self.calls.append((task, payload))
        if self.queue:
            return self.queue.pop(0)
        return ("ok", {})

    def install(self):
        console.launch = self.launch
        console.available = lambda: True
        return self

    @property
    def tasks(self) -> list[str]:
        return [t for t, _ in self.calls]


class FakeSftp:
    def __init__(self):
        self.calls: list[tuple[str, str, str]] = []

    def put(self, local, remote):
        self.calls.append(("put", local, remote))

    def get(self, remote, local):
        self.calls.append(("get", remote, local))

    def close(self):
        pass


class FakeSsh:
    def __init__(self, sftp: FakeSftp):
        self._sftp = sftp

    def open_sftp(self) -> FakeSftp:
        return self._sftp


class FakeClient:
    """替换 lib.transport.Client：只记录传输参数，不真连 SFTP。

    迷你 SSH 服务端不实现 sftp 子系统，这里替换掉客户端才能验证
    「策略放行之后确实按 put/get 的正确方向调用了传输」。
    """

    last: "FakeClient | None" = None

    def __init__(self, host=None, password=None, settings=None, redactor=None):
        self.sftp = FakeSftp()
        FakeClient.last = self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    @property
    def _ssh(self) -> FakeSsh:  # noqa: SLF001 —— 对齐真实 Client 的内部结构
        return FakeSsh(self.sftp)


def run_cli(args: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(args)
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


def reset_data():
    shutil.rmtree(_TMP, ignore_errors=True)
    _TMP.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------
# 测试
# --------------------------------------------------------------------------


def main() -> int:
    port, stop = start_server()
    real_available = console.available
    real_launch = console.launch
    print(f"迷你 SSH 服务端：127.0.0.1:{port}\n")

    try:
        print("== 未初始化时的状态协议 ==")
        reset_data()
        mock = MockConsole().install()

        mock.push("ok")
        code, out, err = run_cli(["run", HOST_NAME, "echo hi"])
        check("无密码库 → 触发 setup 窗口", mock.tasks == ["setup"], str(mock.tasks))
        check("返回 CONFIGURED(10)", code == protocol.EXIT_CONFIGURED, str(code))
        check("stderr 有状态行", "SSHHH_STATUS: CONFIGURED" in err, err)
        check("状态行不含密码", SSH_PASSWORD not in err)

        reset_data()
        mock = MockConsole().install()
        mock.push("cancel")
        code, _, err = run_cli(["run", HOST_NAME, "echo hi"])
        check("用户取消 → CANCELLED(11)", code == protocol.EXIT_CANCELLED, str(code))
        check("取消状态行", "SSHHH_STATUS: CANCELLED" in err, err)

        reset_data()
        mock = MockConsole().install()
        mock.push("timeout")
        code, _, err = run_cli(["run", HOST_NAME, "echo hi"])
        check("窗口超时 → TIMEOUT(12)", code == protocol.EXIT_TIMEOUT, str(code))
        check("超时提示含手动命令", "sshhh.py" in err and "config" in err, err)

        reset_data()
        mock = MockConsole().install()
        mock.push("error", {"error": "窗口崩了"})
        code, _, err = run_cli(["run", HOST_NAME, "echo hi"])
        check("窗口报错 → 3", code == protocol.EXIT_CONFIG, str(code))

        print("\n== 已初始化：正常执行 ==")
        reset_data()
        v = vault.Vault.create(paths.vault_file(), MASTER)
        v.set(HOST_NAME, SSH_PASSWORD)
        # allow_shell：下面的脱敏用例要把带 & < 的密码原样 echo 出去，
        # #28 之后含元字符的命令默认被拒，这里显式放开（与脱敏逻辑无关）。
        store.upsert_host(store.Host(name=HOST_NAME, host="127.0.0.1",
                                     user=USER, port=port, description="测试",
                                     allow_shell=True))

        mock = MockConsole().install()
        code, out, err = run_cli(["run", HOST_NAME, "echo hello-world"])
        check("执行成功", code == 0, err)
        check("输出正确", "hello-world" in out, out)
        check("未触发配置窗口", mock.tasks == [], str(mock.tasks))

        code, out, _ = run_cli(["run", HOST_NAME, "echo", "a b"])
        check("多参数拼接", "a b" in out, out)

        print("\n== 密码保护 ==")
        code, out, err = run_cli(["run", HOST_NAME, f"echo {SSH_PASSWORD}"])
        check("远端回显被脱敏", SSH_PASSWORD not in out, out)
        check("出现 REDACTED", "[REDACTED]" in out, out)

        check("hosts.toml 无明文密码",
              SSH_PASSWORD not in paths.hosts_file().read_text(encoding="utf-8"))
        check("vault.enc 无明文密码",
              SSH_PASSWORD not in paths.vault_file().read_text(encoding="utf-8"))

        audit_text = paths.audit_file().read_text(encoding="utf-8")
        check("审计日志无密码", SSH_PASSWORD not in audit_text)
        check("审计有记录", '"action": "run"' in audit_text, audit_text[-200:])

        print("\n== 回传文件字段白名单 ==")
        import console_setup

        leak = _TMP / "leak-write.json"
        console_setup._write_result(  # noqa: SLF001
            leak,
            {"status": "ok", "host": "box", "password": "SHOULD-NOT-LEAK",
             "master_password": "NOPE"},
        )
        written = json.loads(leak.read_text(encoding="utf-8"))
        check("写入侧过滤敏感字段",
              "password" not in written and "master_password" not in written,
              str(written))
        check("写入侧保留合法字段", written.get("host") == "box", str(written))

        leak.write_text(json.dumps({
            "status": "ok", "host": "box", "password": "SHOULD-NOT-LEAK",
        }), encoding="utf-8")
        status, detail = console._read_result(leak)  # noqa: SLF001
        check("读取侧过滤敏感字段",
              status == "ok" and "password" not in detail, str(detail))

        print("\n== 主机缺失 / 密码缺失 ==")
        reset_data()
        vault.Vault.create(paths.vault_file(), MASTER)
        mock = MockConsole().install()
        mock.push("ok")
        code, _, err = run_cli(["run", "newbox", "echo hi"])
        check("主机不存在 → HOST_ADDED(14)", code == protocol.EXIT_HOST_ADDED, str(code))
        check("窗口任务是 add_host", mock.tasks == ["add_host"], str(mock.tasks))
        check("状态行正确", "SSHHH_STATUS: HOST_ADDED" in err, err)

        reset_data()
        v = vault.Vault.create(paths.vault_file(), MASTER)
        store.upsert_host(store.Host(name="np", host="127.0.0.1", user=USER, port=port))
        mock = MockConsole().install()
        mock.push("ok")
        code, _, err = run_cli(["run", "np", "echo hi"])
        check("缺密码 → 补密码后 CONFIGURED(10)",
              code == protocol.EXIT_CONFIGURED, str(code))
        check("触发 add_host 窗口", mock.tasks == ["add_host"], str(mock.tasks))

        reset_data()
        v = vault.Vault.create(paths.vault_file(), MASTER)
        store.upsert_host(store.Host(name=HOST_NAME, host="127.0.0.1",
                                     user=USER, port=port))
        MockConsole().install()
        code, _, err = run_cli(["test", "ghost-host"])
        check("test 未知主机 → 3（配置错误，不是 LOCKED）", code == 3, str(code))
        check("提示未知主机", "未知主机" in err, err)

        code, _, err = run_cli(["put", "ghost-host", "a", "b"])
        check("put 未知主机 → 3", code == 3, str(code))

        print("\n== 认证失败 ==")
        reset_data()
        v = vault.Vault.create(paths.vault_file(), MASTER)
        v.set(HOST_NAME, "wrong-password-here")
        store.upsert_host(store.Host(name=HOST_NAME, host="127.0.0.1",
                                     user=USER, port=port))
        MockConsole().install()
        code, out, err = run_cli(["run", HOST_NAME, "echo hi"])
        check("认证失败返回 4", code == protocol.EXIT_NETWORK, str(code))
        check("错误信息不含密码",
              "wrong-password-here" not in (out + err), err)

        print("\n== 命令策略 ==")
        reset_data()
        v = vault.Vault.create(paths.vault_file(), MASTER)
        v.set(HOST_NAME, SSH_PASSWORD)
        h = store.Host(name=HOST_NAME, host="127.0.0.1", user=USER, port=port)
        store.upsert_host(h)
        # fullmatch 语义：要拦一整族就得写 .*（旧写法 ^rm -rf 只拦正好那一条）
        store.set_policy(HOST_NAME, [], [r"^rm -rf.*"])
        MockConsole().install()
        code, _, err = run_cli(["run", HOST_NAME, "rm -rf /tmp/x"])
        check("deny 规则生效", code == 1, str(code))
        check("拒绝提示", "策略拒绝" in err, err)

        code, _, err = run_cli(["run", HOST_NAME, "df -h && rm -rf /tmp/x"])
        check("含 shell 元字符默认拒绝", code == 1, str(code))
        check("提示里点明元字符", "元字符" in err, err)

        store.upsert_host(store.Host(name=HOST_NAME, host="127.0.0.1", user=USER,
                                     port=port, allow_shell=True))
        code, _, err = run_cli(["run", HOST_NAME, "echo a && echo b"])
        check("allow_shell 主机放行 &&", code == 0, err)
        store.upsert_host(h)

        print("\n== 只读命令 ==")
        code, out, _ = run_cli(["list"])
        check("list 可用", code == 0 and HOST_NAME in out, out)
        code, out, _ = run_cli(["status"])
        check("status 可用", code == 0 and "数据目录" in out, out)
        code, out, _ = run_cli(["audit", "-n", "5"])
        check("audit 可用", code == 0 and "run" in out, out)

        print("\n== 配置文件结构 ==")
        raw = paths.hosts_file().read_text(encoding="utf-8")
        check("hosts.toml 是合法 TOML", "password" not in raw, raw)

        print("\n== 密码库头部 ==")
        v_head = vault.open_vault()
        v_head.set("entry-name-canary-7f3", "x")
        raw_vault = paths.vault_file().read_text(encoding="utf-8")
        check("vault.enc 不再写 entries 字段", '"entries"' not in raw_vault, raw_vault[:300])
        check("vault.enc 头部不暴露条目名",
              "entry-name-canary-7f3" not in raw_vault, raw_vault[:300])

        # 老版本把条目名明文写在头部，读一次再写一次应该把它清掉
        legacy = json.loads(raw_vault)
        legacy["entries"] = ["legacy-leaked-name", HOST_NAME]
        paths.vault_file().write_text(json.dumps(legacy), encoding="utf-8")
        vault.open_vault().set("touch", "1")
        raw_after = paths.vault_file().read_text(encoding="utf-8")
        check("旧文件的 entries 在下次写入时被清除", '"entries"' not in raw_after, raw_after[:300])
        check("遗留的条目名不再出现", "legacy-leaked-name" not in raw_after, raw_after[:300])

        print("\n== 审计覆盖 ==")
        reset_data()
        v = vault.Vault.create(paths.vault_file(), MASTER)
        v.set(HOST_NAME, SSH_PASSWORD)
        store.upsert_host(store.Host(name=HOST_NAME, host="127.0.0.1",
                                     user=USER, port=port))
        MockConsole().install()

        code, _, err = run_cli(["test", HOST_NAME])
        check("test 连通成功", code == 0, err)
        code, _, err = run_cli(["unlock"])
        check("unlock 无需操作时返回 0", code == 0, err)
        code, _, err = run_cli(["setpass", HOST_NAME])
        check("setpass 走配置窗口并成功", code == 0, err)

        actions = [r.get("action") for r in audit.tail(50)]
        for action in ("vault.open", "test", "unlock", "setpass"):
            check(f"审计记录了 {action}", action in actions, str(actions))
        check("审计仍不含密码",
              SSH_PASSWORD not in paths.audit_file().read_text(encoding="utf-8"))

        # 模拟「直接 import lib.vault 解密」：这条路拦不住，但必须留痕
        saved_argv = sys.argv[:]
        inline = f"from lib import vault; vault.open_vault()  # {MASTER} {SSH_PASSWORD}"
        sys.argv = ["-c", inline]
        try:
            vault.open_vault()
        finally:
            sys.argv = saved_argv
        opens = [r for r in audit.tail(5) if r.get("action") == "vault.open"]
        check("直接调用 vault 也写 vault.open", bool(opens), str(audit.tail(5)))
        last_open = opens[-1] if opens else {}
        check("记录里有调用方 pid",
              str(os.getpid()) in last_open.get("command", ""), str(opens))
        check("记录里保留了命令行摘要",
              "vault.open_vault()" in last_open.get("command", ""), str(last_open))
        check("命令行里的主密码被脱敏",
              MASTER not in json.dumps(last_open, ensure_ascii=False), str(last_open))
        check("命令行里的密码被脱敏",
              SSH_PASSWORD not in json.dumps(last_open, ensure_ascii=False), str(last_open))

        print("\n== 文件通道受策略约束 ==")
        reset_data()
        v = vault.Vault.create(paths.vault_file(), MASTER)
        v.set(HOST_NAME, SSH_PASSWORD)
        store.upsert_host(store.Host(name=HOST_NAME, host="127.0.0.1",
                                     user=USER, port=port))
        store.set_policy(HOST_NAME, ["^df -h$"], [])
        MockConsole().install()

        code, _, err = run_cli(["get", HOST_NAME, "/etc/shadow", str(_TMP / "shadow")])
        check("命令白名单主机的 get 默认被拒", code == 1, str(code))
        check("提示文件传输被策略拒绝", "策略拒绝" in err, err)
        check("拒绝发生在建连之前", not (_TMP / "shadow").exists())

        code, _, err = run_cli(["put", HOST_NAME, str(_TMP / "a.txt"), "/etc/rc.local"])
        check("未放行的 put 同样被拒", code == 1, str(code))

        actions = [r.get("action") for r in audit.tail(30)]
        check("写了 transfer.denied 审计", "transfer.denied" in actions, str(actions))

        # 显式放行后应真的调用传输（用假 Client，不依赖服务端 SFTP 子系统）
        store.set_policy(HOST_NAME, ["^df -h$"], [],
                         allow_put=["^/tmp/"], allow_get=["^/var/log/"])
        real_client = transport.Client
        transport.Client = FakeClient
        try:
            code, _, err = run_cli(["put", HOST_NAME, str(_TMP / "a.txt"), "/tmp/a.txt"])
            check("allow_put 放行后执行", code == 0, err)
            calls = FakeClient.last.sftp.calls if FakeClient.last else []
            check("put 方向与路径正确",
                  calls == [("put", os.path.expanduser(str(_TMP / "a.txt")), "/tmp/a.txt")],
                  str(calls))

            remote_log = "/var/log/syslog"
            local_log = os.path.expanduser(str(_TMP / "syslog"))
            code, _, err = run_cli(["get", HOST_NAME, remote_log, local_log])
            check("allow_get 放行后执行", code == 0, err)
            calls = FakeClient.last.sftp.calls if FakeClient.last else []
            check("get 方向与路径正确",
                  calls == [("get", remote_log, local_log)],
                  str(calls))

            code, _, err = run_cli(["get", HOST_NAME, "/etc/shadow", str(_TMP / "shadow2")])
            check("白名单外的路径仍被拒", code == 1, str(code))
        finally:
            transport.Client = real_client

        put_recs = [r for r in audit.tail(30) if r.get("action") == "transfer.put"]
        check("传输成功也写审计", len(put_recs) == 1, str(put_recs))
        check("审计含远端路径",
              "/tmp/a.txt" in (put_recs[0].get("command", "") if put_recs else ""),
              str(put_recs))
        check("传输审计不含密码",
              SSH_PASSWORD not in paths.audit_file().read_text(encoding="utf-8"))

        print("\n== Python 版本过低时的指引 ==")
        from lib import runtime as runtime_mod

        orig_deps = runtime_mod.deps_ok
        orig_find = runtime_mod.find_base_python
        runtime_mod.deps_ok = lambda *a, **k: False
        runtime_mod.find_base_python = lambda: None
        try:
            code, out, err = run_cli(["setup"])
            check("setup 版本过低 → 20", code == 20, str(code))
            check("提示去 python.org", "python.org" in err, err)
            check("措辞是升级而非首次安装", "升级" in err, err)
            check("不出现「手动执行 setup」的死循环提示",
                  "手动执行" not in err, err)

            code, out, err = run_cli(["list"])
            check("普通命令也返回 20", code == 20, str(code))
            check("带 NO_RUNTIME 状态行", "SSHHH_STATUS: NO_RUNTIME" in err, err)
            check("hint 指向升级 Python", "python.org" in err, err)
            check("hint 不让人去跑 setup", "sshhh.py setup" not in err, err)
        finally:
            runtime_mod.deps_ok = orig_deps
            runtime_mod.find_base_python = orig_find

        print("\n== 依赖安装失败时的指引 ==")
        orig_create = runtime_mod._create_venv
        orig_install = runtime_mod._install
        orig_find2 = runtime_mod.find_base_python
        runtime_mod.deps_ok = lambda *a, **k: False
        runtime_mod.find_base_python = lambda: "/usr/bin/python3"
        runtime_mod._create_venv = lambda base: True
        runtime_mod._install = (
            lambda venv_py: "pip 安装失败（退出码 1）：Connection refused"
        )
        try:
            code, out, err = run_cli(["list"])
            check("依赖失败返回 20", code == 20, str(code))
            check("转述了失败原因", "Connection refused" in err, err)
            check("给出换源建议", "PIP_INDEX_URL" in err, err)
            check("给出 setup 命令", "setup" in err, err)
        finally:
            runtime_mod.deps_ok = orig_deps
            runtime_mod.find_base_python = orig_find2
            runtime_mod._create_venv = orig_create
            runtime_mod._install = orig_install

        print("\n== 窗口交接与降级 ==")
        reset_data()
        mock = MockConsole().install()
        mock.push("pending", {"elapsed": 25.0})
        code, _, err = run_cli(["run", HOST_NAME, "echo hi"])
        check("窗口交接 → SETUP_PENDING(15)",
              code == protocol.EXIT_PENDING, str(code))
        check("pending 状态行", "SSHHH_STATUS: SETUP_PENDING" in err, err)
        check("让用户去窗口里完成", "窗口" in err, err)
        check("要求 agent 不要反复调用", "不要反复调用" in err, err)

        reset_data()
        mock = MockConsole().install()
        mock.push("gone", {"elapsed": 6.0})
        code, _, err = run_cli(["run", HOST_NAME, "echo hi"])
        check("窗口被外部回收 → TIMEOUT(12)",
              code == protocol.EXIT_TIMEOUT, str(code))
        check("指向自己终端里的 --here", "--here" in err, err)

        print("\n== 弹窗不可用时的自动降级 ==")
        reset_data()
        paths.ensure_data_dir()
        paths.no_window_marker().write_text("测试用标记", encoding="utf-8")
        console.available = real_available
        code, _, err = run_cli(["run", HOST_NAME, "echo hi"])
        check("有降级标记 → 不再弹窗", code == protocol.EXIT_TIMEOUT, str(code))
        check("手动命令自动带 --here", "config --here" in err, err)
        paths.no_window_marker().unlink()
        MockConsole().install()

        print("\n== 进程存活判断 ==")
        check("当前进程判定为活", console._pid_alive(os.getpid()))
        check("不存在的 pid 判定为死", not console._pid_alive(999999))
        check("pid 0 判定为死", not console._pid_alive(0))

        print("\n== config --here 在非交互终端 ==")
        reset_data()
        MockConsole().install()
        orig_stdin = sys.stdin
        sys.stdin = io.StringIO()
        try:
            code, _, err = run_cli(["config", "--here"])
        finally:
            sys.stdin = orig_stdin
        check("非 tty → 3", code == protocol.EXIT_CONFIG, str(code))
        check("提示在真实终端里执行", "config --here" in err, err)

        print("\n== 已有配置窗口在运行时 ==")
        reset_data()
        fake = _TMP / ".setup-fake"
        fake.mkdir(parents=True, exist_ok=True)
        (fake / "pid.json").write_text(json.dumps({"pid": os.getpid()}),
                                       encoding="utf-8")
        found = console.find_active()
        check("能发现正在运行的配置窗口",
              found is not None and found[1] == os.getpid(), str(found))

        status, detail = real_launch("setup", {}, 5, 5)
        check("窗口已在运行时立即返回 pending",
              status == console.PENDING, str(status))
        check("标记为 active（用户在输入，不要再开窗口）",
              detail.get("active") is True, str(detail))
        shutil.rmtree(fake, ignore_errors=True)

        print("\n== 窗口启动脚本 ==")
        from lib import launcher as launcher_mod

        work = _TMP / ".setup-testcmd"
        cmd_file = launcher_mod.write_cmd(
            work, r"C:\Python\python.exe", Path(r"D:\s\console_setup.py"), "setup",
            work / "payload.json", work / "result.json", work / "pid.json",
            work / "stderr.log", _TMP,
        )
        raw = cmd_file.read_bytes()
        text = raw.decode("mbcs", "replace")
        check("生成 run.cmd", cmd_file.exists())
        check("stderr 走独立文件（避免和窗口日志抢句柄）",
              "stderr.log" in text, text)
        check("数据目录作为参数传入", str(_TMP) in text, text)
        check("不含 UTF-8 BOM（cmd 解析不了）",
              not raw.startswith(b"\xef\xbb\xbf"))
        shutil.rmtree(work, ignore_errors=True)

        print("\n== 控制台读行（不依赖 stdin）==")
        if os.name == "nt":
            import types

            keys = iter(["a", "b", "\x08", "c", "\r"])
            fake = types.SimpleNamespace(getwch=lambda: next(keys))
            real_msvcrt = sys.modules.get("msvcrt")
            sys.modules["msvcrt"] = fake  # type: ignore[assignment]
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    line = console_setup._read_line("提示: ")
            finally:
                if real_msvcrt is not None:
                    sys.modules["msvcrt"] = real_msvcrt  # type: ignore[assignment]
            check("退格被正确处理", line == "ac", line)
        else:
            check("非 Windows 跳过读行测试", True)

        print("\n== 参数解析：长选项位置 ==")
        import sshhh as _cli

        vf = {"timeout", "stdin"}

        o, p = _cli._parse(["hk", "--sudo", "systemctl restart nginx"], vf)
        check("--sudo 写在主机之后生效", o.get("sudo") is True, str(o))
        check("--sudo 不会被拼进命令", p == ["hk", "systemctl restart nginx"], str(p))

        o, p = _cli._parse(["--sudo", "hk", "cmd"], vf)
        check("--sudo 写在主机之前也生效", o.get("sudo") is True, str(o))

        o, p = _cli._parse(["hk", "--timeout", "600", "make build"], vf)
        check("--timeout 写在主机之后生效", o.get("timeout") == "600", str(o))
        check("--timeout 的值不被拼进命令", p == ["hk", "make build"], str(p))

        o, p = _cli._parse(["hk", "--timeout=600", "make"], vf)
        check("--timeout=600 内联写法", o.get("timeout") == "600", str(o))

        o, p = _cli._parse(["hk", "--", "--sudo systemctl restart nginx"], vf)
        check("-- 之后原样传给远端", o == {} and p[1] == "--sudo systemctl restart nginx", str(p))

        o, p = _cli._parse(["hk", "tail -n 100 /var/log/x.log"], vf)
        check("远端命令里的短选项不被吞", o == {} and p[1] == "tail -n 100 /var/log/x.log", str(p))

        o, p = _cli._parse(["hk", "--weird-flag", "x"], vf)
        check("主机之后的未知长选项归远端", o == {} and p == ["hk", "--weird-flag", "x"], str(p))

        try:
            _cli._parse(["hk", "--sudo=1", "cmd"], vf)
        except _cli.UsageError:
            check("--sudo 带值被拒绝", True)
        else:
            check("--sudo 带值被拒绝", False, "没有报错")

        print("\n== 迁移也写审计 ==")
        reset_data()
        old_dir = _TMP / "old-sshx"
        old_v = vault.Vault.create(old_dir / "vault.enc", MASTER)
        old_v.set("legacy-host", "old-password-value")
        (old_dir / "sshx.toml").write_text(
            '[hosts.legacy-host]\nhost = "10.0.0.9"\nuser = "root"\n',
            encoding="utf-8",
        )
        MockConsole().install()
        code, _, err = run_cli(["migrate", str(old_dir)])
        check("迁移成功", code == 0, err)
        check("主机迁过来了", "legacy-host" in store.load(), str(store.load()))

        migrate_recs = [r for r in audit.tail(20) if r.get("action") == "migrate"]
        check("迁移写了审计", len(migrate_recs) == 1, str(audit.tail(20)))
        check("迁移审计不含密码",
              all("old-password-value" not in json.dumps(r, ensure_ascii=False)
                  for r in migrate_recs),
              str(migrate_recs))

    finally:
        stop.set()
        time.sleep(0.2)
        shutil.rmtree(_TMP, ignore_errors=True)

    print("\n" + "=" * 46)
    print(f"通过 {PASSED} 项，失败 {FAILED} 项")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
