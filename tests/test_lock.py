"""并发锁测试。

协议里承诺「多个 agent 同时触发配置时，后到的会等待而不是写坏数据」，
这里用真实多进程验证三件事：

1. 锁真的互斥——第二个进程必须等第一个释放
2. 等待超过 30 秒上限时抛 LockTimeout（而不是无限阻塞）
3. 并发写入不会丢数据（没有 read-modify-write 竞争）

运行：
    D:/work/agentssh/.venv/Scripts/python.exe tests/test_lock.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

MASTER = "lock-test-master-4b2e"

_TMP = Path(tempfile.mkdtemp(prefix="sshhh-lock-"))
os.environ["SSHHH_DATA_DIR"] = str(_TMP)
os.environ["SSHHH_MASTER"] = MASTER

from lib import paths, store, vault  # noqa: E402
from lib.lock import LockTimeout, data_lock  # noqa: E402

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


# --------------------------------------------------------------------------
# 子进程 worker
# --------------------------------------------------------------------------

WORKER = r"""
import json, sys, time
sys.path.insert(0, sys.argv[1])
from lib.lock import LockTimeout, data_lock
from lib import vault

mode, name, hold, timeout = sys.argv[2], sys.argv[3], float(sys.argv[4]), float(sys.argv[5])
out = {"ok": False, "wait": None}

t0 = time.monotonic()
try:
    with data_lock(timeout=timeout):
        out["wait"] = time.monotonic() - t0
        if mode == "write":
            v = vault.open_vault()
            v.set(name, "value-of-" + name)
            time.sleep(hold)
        else:
            time.sleep(hold)
    out["ok"] = True
except LockTimeout:
    out["wait"] = time.monotonic() - t0
    out["error"] = "lock_timeout"
except Exception as exc:
    out["error"] = type(exc).__name__ + ": " + str(exc)

print(json.dumps(out))
"""


def worker_cmd(mode: str, name: str, hold: float, timeout: float = 30.0) -> list[str]:
    return [sys.executable, "-c", WORKER, str(SCRIPTS), mode, name,
            str(hold), str(timeout)]


def run_worker(mode: str, name: str, hold: float, timeout: float = 30.0) -> dict:
    proc = subprocess.run(
        worker_cmd(mode, name, hold, timeout),
        capture_output=True, text=True, encoding="utf-8", timeout=120,
    )
    line = (proc.stdout or "").strip().splitlines()
    if not line:
        return {"ok": False, "error": f"无输出: {proc.stderr[-300:]}"}
    try:
        return json.loads(line[-1])
    except json.JSONDecodeError:
        return {"ok": False, "error": f"输出异常: {proc.stdout[-200:]}"}


STORE_WORKER = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
from lib import store
out = {"ok": True}
try:
    store.upsert_host(store.Host(name=sys.argv[2], host="10.0.0.1",
                                 user="root", description="并发写入"))
except Exception as exc:
    out = {"ok": False, "error": type(exc).__name__ + ": " + str(exc)}
print(json.dumps(out))
"""

READER = r"""
import json, sys, time
sys.path.insert(0, sys.argv[1])
from lib import store
bad = []
reads = 0
end = time.monotonic() + float(sys.argv[2])
while time.monotonic() < end:
    try:
        store.load()
        reads += 1
    except Exception as exc:
        bad.append(type(exc).__name__ + ": " + str(exc))
print(json.dumps({"bad": bad, "reads": reads}))
"""


ENSURE_WORKER = r"""
import json, sys, time
sys.path.insert(0, sys.argv[1])
from lib import paths, runtime

delay = float(sys.argv[2])
marker = paths.venv_dir() / ".stub-ready"
calls = []

def fake_deps(executable):
    return marker.exists()

def fake_create(base):
    calls.append("create")
    time.sleep(delay)                        # 假装在建 venv
    venv_py = paths.venv_python()
    venv_py.parent.mkdir(parents=True, exist_ok=True)
    venv_py.write_text("")
    return True

def fake_install(venv_py):
    calls.append("install")
    time.sleep(delay)                        # 假装在 pip install
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("1")
    return None

runtime.deps_ok = fake_deps
runtime.find_base_python = lambda: "/usr/bin/python3"
runtime._create_venv = fake_create
runtime._install = fake_install
runtime._reexec = lambda exe: calls.append("reexec")

try:
    runtime.ensure()
    print(json.dumps({"ok": True, "calls": calls}))
except Exception as exc:
    print(json.dumps({"ok": False, "calls": calls,
                      "error": type(exc).__name__ + ": " + str(exc)}))
"""

ENSURE_TIMEOUT_WORKER = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
from lib import runtime

runtime.BOOTSTRAP_LOCK_TIMEOUT = 0.4
runtime.deps_ok = lambda *a, **k: False
try:
    runtime.ensure()
    print(json.dumps({"ok": True}))
except runtime.RuntimeError_ as exc:
    print(json.dumps({"ok": False, "error": "RuntimeError_", "msg": str(exc)}))
except Exception as exc:
    print(json.dumps({"ok": False, "error": type(exc).__name__, "msg": str(exc)}))
"""


def main() -> int:
    # 准备一个可用的密码库
    vault.Vault.create(paths.vault_file(), MASTER)

    print("== 锁互斥：后到的必须等待 ==")
    holder = subprocess.Popen(
        worker_cmd("hold", "holder", 1.4), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="utf-8",
    )
    time.sleep(0.35)  # 确保 holder 先拿到锁

    t0 = time.monotonic()
    second = run_worker("write", "second", 0.0, timeout=20)
    elapsed = time.monotonic() - t0
    holder.wait(timeout=30)

    check("第二个进程成功拿到锁", second.get("ok") is True, str(second))
    waited = second.get("wait") or 0
    check("确实等待了（>=0.8s）", waited >= 0.8, f"wait={waited:.2f}s")
    check("总耗时不异常", elapsed < 10, f"{elapsed:.1f}s")

    print("\n== 锁超时：不能无限阻塞 ==")
    holder2 = subprocess.Popen(
        worker_cmd("hold", "holder2", 3.0), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="utf-8",
    )
    time.sleep(0.35)

    t0 = time.monotonic()
    blocked = run_worker("hold", "blocked", 0.0, timeout=0.6)
    blocked_elapsed = time.monotonic() - t0
    holder2.wait(timeout=30)

    check("超时后抛出 LockTimeout",
          blocked.get("error") == "lock_timeout", str(blocked))
    check("没有无限等待（<3s）", blocked_elapsed < 3.0, f"{blocked_elapsed:.1f}s")

    print("\n== 并发写入不丢数据 ==")
    names = [f"host{i}" for i in range(6)]
    procs = [
        subprocess.Popen(
            worker_cmd("write", n, 0.15),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8",
        )
        for n in names
    ]
    results = []
    for p in procs:
        out, err = p.communicate(timeout=120)
        try:
            results.append(json.loads(out.strip().splitlines()[-1]))
        except Exception:
            results.append({"ok": False, "error": err[-200:]})

    check("6 个并发写入全部成功",
          all(r.get("ok") for r in results),
          str([r for r in results if not r.get("ok")]))

    final = vault.Vault.open(paths.vault_file(), master=MASTER, allow_keyring=False)
    stored = set(final.names())
    missing = [n for n in names if n not in stored]
    check("没有丢更新", not missing, f"缺失 {missing}，实际 {sorted(stored)}")
    check("值都正确",
          all(final.get(n) == f"value-of-{n}" for n in names))

    print("\n== 只读操作不被阻塞 ==")
    holder3 = subprocess.Popen(
        worker_cmd("hold", "holder3", 1.5), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="utf-8",
    )
    time.sleep(0.3)
    t0 = time.monotonic()
    v = vault.Vault.open(paths.vault_file(), master=MASTER, allow_keyring=False)
    _ = v.names()
    read_elapsed = time.monotonic() - t0
    holder3.wait(timeout=30)
    check("读操作无需等锁（<0.5s）", read_elapsed < 0.5, f"{read_elapsed:.2f}s")

    print("\n== 并发读不会读到半截 TOML（#9）==")
    reader = subprocess.Popen(
        [sys.executable, "-c", READER, str(SCRIPTS), "2.5"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8",
    )
    writes = 0
    while reader.poll() is None and writes < 400:
        store.upsert_host(store.Host(name=f"churn{writes % 7}",
                                     host=f"10.1.0.{writes % 250}",
                                     user="root", description="x" * (writes % 200)))
        writes += 1
    out, err = reader.communicate(timeout=60)
    try:
        report = json.loads(out.strip().splitlines()[-1])
    except Exception:
        report = {"bad": [err[-200:]], "reads": 0}
    check("读方一次解析失败都没有",
          not report["bad"], f"失败 {len(report['bad'])} 次：{report['bad'][:3]}")
    check("读方确实在并发读", (report.get("reads") or 0) > 20, str(report))
    check("写方也确实在写", writes > 20, str(writes))

    print("\n== store 写函数自带锁，调用方不必记得加锁（#9）==")
    names = [f"locked{i}" for i in range(6)]
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", STORE_WORKER, str(SCRIPTS), n],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8",
        )
        for n in names
    ]
    results = []
    for p in procs:
        out, err = p.communicate(timeout=120)
        try:
            results.append(json.loads(out.strip().splitlines()[-1]))
        except Exception:
            results.append({"ok": False, "error": err[-200:]})
    check("六个进程不加外层锁也全部成功",
          all(r.get("ok") for r in results),
          str([r for r in results if not r.get("ok")]))
    stored = store.load()
    missing = [n for n in names if n not in stored]
    check("没有丢更新", not missing, f"缺失 {missing}")
    check("写入后清单仍合法", all(stored[n].user == "root" for n in names))

    print("\n== 锁可重入：锁内调 store 不会自己等自己（#9）==")
    t0 = time.monotonic()
    try:
        with data_lock(timeout=5):
            store.upsert_host(store.Host(name="nested", host="10.2.2.2",
                                         user="root"))
            store.set_policy("nested", ["^ls$"], [])
            nested = store.get("nested")
        reentrant_error = None
    except LockTimeout as exc:
        reentrant_error = str(exc)
        nested = None
    elapsed = time.monotonic() - t0
    check("嵌套调用不超时", reentrant_error is None, str(reentrant_error))
    check("嵌套调用很快返回（<2s）", elapsed < 2.0, f"{elapsed:.2f}s")
    check("嵌套调用结果正确",
          nested is not None and nested.policy.allow == ["^ls$"], str(nested))

    print("\n== 并发首跑只建一次 venv（#10）==")
    shutil.rmtree(paths.venv_dir(), ignore_errors=True)
    workers = [
        subprocess.Popen(
            [sys.executable, "-c", ENSURE_WORKER, str(SCRIPTS), "0.9"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8",
        )
        for _ in range(3)
    ]
    reports = []
    for p in workers:
        out, err = p.communicate(timeout=180)
        try:
            reports.append(json.loads(out.strip().splitlines()[-1]))
        except Exception:
            reports.append({"ok": False, "calls": [], "error": err[-300:]})

    check("三个并发首跑都成功", all(r.get("ok") for r in reports),
          str([r for r in reports if not r.get("ok")]))
    creates = sum(r.get("calls", []).count("create") for r in reports)
    installs = sum(r.get("calls", []).count("install") for r in reports)
    check("venv 只被建了一次", creates == 1, str([r.get("calls") for r in reports]))
    check("依赖只装了一次", installs == 1, str([r.get("calls") for r in reports]))
    reused = [r for r in reports if r.get("calls") == ["reexec"]]
    check("后到的进程直接复用现成环境", len(reused) == len(reports) - 1,
          str([r.get("calls") for r in reports]))

    print("\n== 等不到自举锁时给状态而不是无限等（#10）==")
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import sys, time; sys.path.insert(0, sys.argv[1]);"
         "from lib.lock import bootstrap_lock;"
         "\nwith bootstrap_lock(timeout=5):\n    time.sleep(2.0)\n",
         str(SCRIPTS)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8",
    )
    time.sleep(0.4)
    t0 = time.monotonic()
    wait = subprocess.run(
        [sys.executable, "-c", ENSURE_TIMEOUT_WORKER, str(SCRIPTS)],
        capture_output=True, text=True, encoding="utf-8", timeout=120,
    )
    waited = time.monotonic() - t0
    holder.communicate(timeout=60)
    try:
        report = json.loads((wait.stdout or "").strip().splitlines()[-1])
    except Exception:
        report = {"error": "输出异常", "msg": wait.stderr[-200:]}
    check("抛的是 RuntimeError_（→ NO_RUNTIME）而不是 LockTimeout",
          report.get("error") == "RuntimeError_", str(report))
    check("提示语说明另一个进程在准备环境",
          "准备运行环境" in str(report.get("msg", "")), str(report))
    check("没有无限等待（<5s）", waited < 5.0, f"{waited:.1f}s")

    shutil.rmtree(_TMP, ignore_errors=True)
    print("\n" + "=" * 46)
    print(f"通过 {PASSED} 项，失败 {FAILED} 项")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
