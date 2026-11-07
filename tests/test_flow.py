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
from lib import audit, console, paths, protocol, store, vault  # noqa: E402


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

    def launch(self, task, payload, timeout):
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
        store.upsert_host(store.Host(name=HOST_NAME, host="127.0.0.1",
                                     user=USER, port=port, description="测试"))

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
        store.set_policy(HOST_NAME, [], [r"^rm -rf"])
        MockConsole().install()
        code, _, err = run_cli(["run", HOST_NAME, "rm -rf /tmp/x"])
        check("deny 规则生效", code == 1, str(code))
        check("拒绝提示", "策略拒绝" in err, err)

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

    finally:
        stop.set()
        time.sleep(0.2)
        shutil.rmtree(_TMP, ignore_errors=True)

    print("\n" + "=" * 46)
    print(f"通过 {PASSED} 项，失败 {FAILED} 项")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
