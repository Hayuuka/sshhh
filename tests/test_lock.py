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

from lib import paths, vault  # noqa: E402

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

    shutil.rmtree(_TMP, ignore_errors=True)
    print("\n" + "=" * 46)
    print(f"通过 {PASSED} 项，失败 {FAILED} 项")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
