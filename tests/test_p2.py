"""P2 基线完善：hosts.toml 完整性与密钥认证。

按 docs/DESIGN.md §6 的 P2 行组织，每段对应一个 issue：

  #18 hosts.toml 完整性：HMAC 签名、fail-closed、防洗白写规则、reseal
  #18 key_file 托管旁路封堵、SSHHH_DATA_DIR 测试模式门禁
  #3  密钥生成 / 导入 / 展示（vault key:<host>）、密钥优先与回落留痕

运行：
    ~/.sshhh/venv/Scripts/python.exe tests/test_p2.py
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

MASTER = "p2-master-passphrase-11a4"

_TMP = Path(tempfile.mkdtemp(prefix="sshhh-p2-"))
os.environ["SSHHH_DATA_DIR"] = str(_TMP)
os.environ["SSHHH_MASTER"] = MASTER
os.environ.pop("SSHHH_TEST_MODE", None)

import sshhh as cli  # noqa: E402
from lib import audit, integrity, paths, store, vault  # noqa: E402

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


def run_cli(args: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(args)
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


def setup_sealed_host(policy: list[str] | None = None) -> None:
    """建库 + 建一台带签名的 prod 主机。policy 非空时加命令白名单。"""
    v = vault.Vault.create(paths.vault_file(), MASTER)
    host = store.Host(name="prod", host="127.0.0.1", user="root", port=22)
    store.upsert_host(host)
    if policy:
        store.set_policy("prod", policy, [])
    v.set("prod", "prod-password-9")
    assert integrity.mac_key() is not None


# --------------------------------------------------------------------------
# #18 hosts.toml 完整性：签名往返与篡改检测
# --------------------------------------------------------------------------


def test_seal_roundtrip_and_tamper() -> None:
    print("\n== #18 签名往返 ==")
    reset()
    setup_sealed_host()

    raw = paths.hosts_file().read_text(encoding="utf-8")
    doc = tomllib.loads(raw)
    check("写入即签名", integrity.SECTION in doc, raw[:200])
    seal = doc[integrity.SECTION]
    check("签名段带方案标识", seal.get("scheme") == integrity.SCHEME, str(seal))
    check("签名密钥已从主密码派生", integrity.mac_key() is not None)
    h = store.get("prod")
    check("合法签名下读路径正常", h is not None and h.name == "prod")

    print("\n== #18 篡改检测（fail-closed）==")
    # 文本手术：删掉策略段，正是 TM-B3 里「删段即永久豁免」的那条路。
    # agent 没有签名密钥，只能把签名段一起删掉
    import tomli_w

    doc = tomllib.loads(paths.hosts_file().read_text(encoding="utf-8"))
    doc["hosts"]["prod"]["policy"] = {"allow": ["^df -h$"]}
    paths.hosts_file().write_text(
        tomli_w.dumps(doc), encoding="utf-8")
    err = None
    try:
        store.get("prod")
    except store.StoreError as exc:
        err = exc
    check("改白名单被拒绝", err is not None, str(err))
    if err is not None:
        check("报错含 reseal 指引", "reseal" in str(err), str(err))

    # agent 干脆把签名段也删掉：一样 fail-closed（没有签名的清单不可信）
    doc.pop(integrity.SECTION, None)
    doc["hosts"]["prod"].pop("policy", None)
    paths.hosts_file().write_text(
        tomli_w.dumps(doc), encoding="utf-8")
    err = None
    try:
        store.get("prod")
    except store.StoreError as exc:
        err = exc
    check("删策略段 + 删签名被拒绝", err is not None, str(err))

    # 注入 key_file 字段（TM-B3 的托管旁路形态）
    reset()
    setup_sealed_host()
    raw = paths.hosts_file().read_text(encoding="utf-8")
    injected = raw.replace('user = "root"', 'user = "root"\nkey_file = "~/.ssh/id_ed25519"')
    paths.hosts_file().write_text(injected, encoding="utf-8")
    err = None
    try:
        store.get("prod")
    except store.StoreError as exc:
        err = exc
    check("注入 key_file 被拒绝", err is not None, str(err))

    # 改一个地址字段：更隐蔽的改法同样要被拦
    reset()
    setup_sealed_host()
    raw = paths.hosts_file().read_text(encoding="utf-8")
    paths.hosts_file().write_text(
        raw.replace('host = "127.0.0.1"', 'host = "6.6.6.6"'), encoding="utf-8")
    err = None
    try:
        store.get("prod")
    except store.StoreError as exc:
        err = exc
    check("改地址被拒绝", err is not None, str(err))

    print("\n== #18 注释与排版不参与签名 ==")
    reset()
    setup_sealed_host()
    raw = paths.hosts_file().read_text(encoding="utf-8")
    annotated = "# 用户手写的注释行\n\n" + raw
    paths.hosts_file().write_text(annotated, encoding="utf-8")
    h = None
    err = None
    try:
        h = store.get("prod")
    except store.StoreError as exc:
        err = exc
    check("加注释不破坏签名", err is None and h is not None, str(err))

    print("\n== #18 空清单不要求签名 ==")
    reset()
    vault.Vault.create(paths.vault_file(), MASTER)
    paths.hosts_file().write_text("# 还没有任何主机\n", encoding="utf-8")
    err = None
    try:
        hosts = store.load()
    except store.StoreError as exc:
        err = exc
    check("空清单可读", err is None and hosts == {}, str(err))


# --------------------------------------------------------------------------
# #18 fail-closed 与 reseal
# --------------------------------------------------------------------------


def test_unsealed_failclosed_and_reseal() -> None:
    print("\n== #18 遗留未签文件 fail-closed ==")
    reset()
    vault.Vault.create(paths.vault_file(), MASTER)
    paths.hosts_file().write_text(
        "[hosts.prod]\n"
        'host = "127.0.0.1"\n'
        'user = "root"\n',
        encoding="utf-8",
    )
    err = None
    try:
        store.get("prod")
    except store.StoreError as exc:
        err = exc
    check("未签清单拒绝读", err is not None, str(err))
    if err is not None:
        check("报错说明签名缺失", "签名" in str(err), str(err))

    print("\n== #18 manage reseal 恢复 ==")
    code, out, err_out = run_cli(["manage", "reseal"])
    check("reseal 退出码 0", code == 0, f"{out}{err_out}")
    h = store.get("prod")
    check("reseal 后恢复可读", h is not None and h.host == "127.0.0.1")
    actions = [r.get("action") for r in audit.tail(5, include_internal=True)]
    check("reseal 写审计", "reseal" in actions, str(actions))

    print("\n== #18 防洗白：篡改后的普通写入不签名 ==")
    reset()
    setup_sealed_host(policy=["^df -h$"])
    # 篡改策略字段（upsert 不会覆盖它）：把白名单改成放行一切
    import tomli_w

    doc = tomllib.loads(paths.hosts_file().read_text(encoding="utf-8"))
    doc["hosts"]["prod"]["policy"]["allow"] = [".*"]
    paths.hosts_file().write_text(tomli_w.dumps(doc), encoding="utf-8")
    err = None
    try:
        store.get("prod")
    except store.StoreError as exc:
        err = exc
    check("篡改后先被拒", err is not None, str(err))
    # 模拟 agent 顺手调一次内部写函数（向导就是这么调的）：写入必须成功
    #（向导场景不能因为清单被动过就卡死用户），但被篡改的策略原样保留、
    # 产物不得带有效签名 —— 否则一次普通写入就把篡改洗白了
    store.upsert_host(store.Host(name="prod", host="127.0.0.1", user="root"))
    err = None
    try:
        store.get("prod")
    except store.StoreError as exc:
        err = exc
    check("写入后仍然 fail-closed（没有被洗白）", err is not None, str(err))
    code, out, err_out = run_cli(["manage", "reseal"])
    check("用户显式 reseal 后恢复", code == 0 and store.get("prod") is not None,
          f"{out}{err_out}")

    print("\n== #18 对已签名文件的写入必须持钥 ==")
    reset()
    setup_sealed_host()
    worker = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "import os; os.environ.pop('SSHHH_MASTER', None); "
        "from lib import store\n"
        "try:\n"
        "    store.upsert_host(store.Host(name='x', host='1.1.1.1', user='r'))\n"
        "    print('NO-ERROR')\n"
        "except Exception as exc:\n"
        "    print(type(exc).__name__)"
    )
    proc = subprocess.run(
        [sys.executable, "-I", "-c", worker, str(SCRIPTS)],
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    check("无钥写入被拒绝", proc.stdout.strip() == "StoreError",
          f"{proc.stdout[-200:]}{proc.stderr[-200:]}")

    print("\n== #18 清单损坏时 reseal 拒绝执行 ==")
    paths.hosts_file().write_text("[hosts.bad\nhost = ", encoding="utf-8")
    before = paths.hosts_file().read_text(encoding="utf-8")
    code, out, err_out = run_cli(["manage", "reseal"])
    check("reseal 对坏文件退出码 3", code == 3, f"{out}{err_out}")
    check("坏文件保持原样", paths.hosts_file().read_text(encoding="utf-8") == before)


# --------------------------------------------------------------------------
# #18 CLI 强制路径与只读视图
# --------------------------------------------------------------------------


def test_enforcement_and_views() -> None:
    print("\n== #18 run 在签名失效时建连前中止 ==")
    reset()
    setup_sealed_host()
    raw = paths.hosts_file().read_text(encoding="utf-8")
    paths.hosts_file().write_text(
        raw.replace('user = "root"', 'user = "attacker"'), encoding="utf-8")
    before = [r.get("action") for r in audit.tail(5, include_internal=True)]
    code, out, err = run_cli(["run", "prod", "echo hi"])
    check("退出码 3（配置/状态错误）", code == 3, f"{code} {out}{err}")
    check("报错转达签名失效", "签名" in err, err)
    after = [r.get("action") for r in audit.tail(10, include_internal=True)]
    check("没有产生 run 审计（未触达远端）", "run" not in after, str(after))

    print("\n== #18 test / put 同样被拒 ==")
    code, out, err = run_cli(["test", "prod"])
    check("test 退出码 3", code == 3, f"{out}{err}")
    check("test 报错说明原因", "签名" in err, err)
    code, out, err = run_cli(["put", "prod", "x", "/tmp/x"])
    check("put 退出码 3", code == 3, f"{out}{err}")

    print("\n== #18 只读视图不被验签挡住 ==")
    code, out, err = run_cli(["list"])
    check("list 仍能列出主机", code == 0 and "prod" in out, f"{out}{err}")
    code, out, err = run_cli(["status"])
    check("status 仍能列出主机", code == 0 and "prod" in out, f"{out}{err}")
    code, out, err = run_cli(["manage", "policy", "prod"])
    check("policy 视图可检查被改过的清单", code == 0 and "prod" in out,
          f"{out}{err}")

    print("\n== #18 锁定状态下 list 仍可用 ==")
    saved = os.environ.pop("SSHHH_MASTER", None)
    try:
        reset()
        setup_sealed_host()
        os.environ.pop("SSHHH_MASTER", None)
        code, out, err = run_cli(["list"])
        check("密码库锁定时 list 正常", code == 0 and "prod" in out,
              f"{out}{err}")
    finally:
        if saved is not None:
            os.environ["SSHHH_MASTER"] = saved

    print("\n== #18 真实子进程里的 reseal（无继承绑定）==")
    reset()
    vault.Vault.create(paths.vault_file(), MASTER)
    paths.hosts_file().write_text(
        "[hosts.prod]\n"
        'host = "127.0.0.1"\n'
        'user = "root"\n',
        encoding="utf-8",
    )
    worker = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "import sshhh; sys.exit(sshhh.main(['manage', 'reseal']))"
    )
    env = dict(os.environ)
    env["SSHHH_TEST_MODE"] = "1"  # commit #18c 起必须随 SSHHH_DATA_DIR 一起给
    proc = subprocess.run(
        [sys.executable, "-I", "-c", worker, str(SCRIPTS)],
        capture_output=True, text=True, encoding="utf-8", timeout=120, env=env,
    )
    check("子进程 reseal 退出码 0", proc.returncode == 0,
          f"{proc.stdout[-300:]}{proc.stderr[-300:]}")
    check("子进程 reseal 落盘生效", store.get("prod") is not None)


def main() -> int:
    test_seal_roundtrip_and_tamper()
    test_unsealed_failclosed_and_reseal()
    test_enforcement_and_views()

    print("\n" + "=" * 46)
    print(f"通过 {PASSED} 项，失败 {FAILED} 项")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
