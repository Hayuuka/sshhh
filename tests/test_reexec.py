"""验证 runtime._reexec 的语义。

背景（issue #1）：Windows 上 os.execv 是「spawn 子进程 + 父进程立即退出」的
模拟实现。宿主的典型行为是「等进程退出 → 读捕获的输出」，于是在子进程写出
stdout 之前就判定命令结束，表现为 exit 0 + 空输出，或者输出错位一轮。

第二个问题：Windows 的 os.execv 不做参数引号处理（"a  b" 会被拆成 "a" 和 "b"），
所以 _reexec 必须把 argv 以 list 形式交给 subprocess。

测试刻意 **不用 capture_output**：那样父进程会一直读到管道 EOF，被子进程继承的
写端续命，反而把竞态掩盖掉（旧代码也能"通过"）。这里把 stdout/stderr 重定向到
文件，进程一退出就立刻读，从而如实复现「宿主等退出后读输出」。

本测试不依赖 paramiko/keyring，任何 Python 3.9+ 都能跑：
    python tests/test_reexec.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"

PASSED = 0
FAILED = 0

# 子进程睡这么久再干活，用来判断父进程是否真的等了
CHILD_SLEEP = 0.8
# 判定「父进程等待过」的阈值，留出解释器启动开销
WAIT_THRESHOLD = 0.65
CHILD_EXIT = 7

CHILD_SRC = '''\
import json, sys, time
from pathlib import Path

out = Path(sys.argv[1])
payload = sys.argv[2:]

time.sleep({sleep})
print("CHILD-STDOUT", flush=True)
print("CHILD-STDERR", file=sys.stderr, flush=True)
out.write_text(json.dumps({{"argv": payload}}, ensure_ascii=False), encoding="utf-8")
sys.exit({code})
'''

HELPER_SRC = '''\
import sys
sys.path.insert(0, r"{scripts}")
from pathlib import Path
from lib import runtime

# 测试里把入口换成探针脚本，_reexec 其余逻辑保持原样
runtime._ENTRY = Path(r"{child}")
runtime._reexec(Path(sys.executable))
'''


def check(name: str, cond: bool, detail: object = "") -> None:
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  [ok] {name}")
    else:
        FAILED += 1
        print(f"  [FAIL] {name}  {detail}")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="sshhh-reexec-"))
    child = tmp / "child.py"
    helper = tmp / "helper.py"
    marker = tmp / "argv.json"
    out_file = tmp / "stdout.txt"
    err_file = tmp / "stderr.txt"

    child.write_text(
        CHILD_SRC.format(sleep=CHILD_SLEEP, code=CHILD_EXIT), encoding="utf-8"
    )
    helper.write_text(
        HELPER_SRC.format(scripts=SCRIPTS, child=child), encoding="utf-8"
    )

    # 参数里刻意放双空格、制表符和引号：execv 拆分时会被破坏
    payload = ["a  b", "c\td", "it's"]

    print(f"平台: {os.name} | 解释器: {sys.executable}")

    print("\n== 父进程必须等子进程结束 ==")
    t0 = time.time()
    with open(out_file, "w", encoding="utf-8") as fo, \
            open(err_file, "w", encoding="utf-8") as fe:
        proc = subprocess.run(
            [sys.executable, str(helper), str(marker), *payload],
            stdout=fo, stderr=fe, timeout=60,
        )
    elapsed = time.time() - t0

    # 关键：进程刚退出就读，不等任何东西 —— 这正是宿主的做法
    out_now = out_file.read_text(encoding="utf-8", errors="replace")
    err_now = err_file.read_text(encoding="utf-8", errors="replace")

    check(
        f"父进程等待了子进程（耗时 {elapsed:.2f}s ≥ {WAIT_THRESHOLD}s）",
        elapsed >= WAIT_THRESHOLD,
        f"实际 {elapsed:.2f}s —— 父进程先退出了",
    )
    check("退出时 stdout 已写完（不再有竞态）",
          "CHILD-STDOUT" in out_now, out_now[:120])
    check("退出时 stderr 已写完",
          "CHILD-STDERR" in err_now, err_now[:120])

    print("\n== 退出码透传 ==")
    check(f"子进程 exit {CHILD_EXIT} → 父进程 {proc.returncode}",
          proc.returncode == CHILD_EXIT, proc.returncode)

    print("\n== 参数原样传递（引号不被拆散）==")
    if marker.exists():
        argv = json.loads(marker.read_text(encoding="utf-8")).get("argv", [])
        check("参数个数一致", len(argv) == len(payload), argv)
        check("参数内容逐项一致", argv == payload, f"{argv!r} != {payload!r}")
    else:
        check("参数个数一致", False, "退出时结果文件还不存在")
        check("参数内容逐项一致", False, "退出时结果文件还不存在")

    # 旧实现下子进程会变成孤儿继续跑，等它收尾再清理，避免删不掉
    time.sleep(CHILD_SLEEP + 0.5)
    import shutil

    shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 46)
    print(f"通过 {PASSED} 项，失败 {FAILED} 项")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
