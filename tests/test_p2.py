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
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # 3.9/3.10 用 pip 的 tomli（与 lib.store 一致）
    import tomli as tomllib  # type: ignore[import-not-found,no-redef]

import paramiko

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

MASTER = "p2-master-passphrase-11a4"

_TMP = Path(tempfile.mkdtemp(prefix="sshhh-p2-"))
os.environ["SSHHH_DATA_DIR"] = str(_TMP)
os.environ["SSHHH_TEST_MODE"] = "1"  # SSHHH_DATA_DIR 仅测试模式生效（#18）
os.environ["SSHHH_MASTER"] = MASTER

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
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=120, env=env,
    )
    check("子进程 reseal 退出码 0", proc.returncode == 0,
          f"{proc.stdout[-300:]}{proc.stderr[-300:]}")
    check("子进程 reseal 落盘生效", store.get("prod") is not None)


# --------------------------------------------------------------------------
# #18 SSHHH_DATA_DIR 仅测试模式生效
# --------------------------------------------------------------------------


def test_data_dir_gating() -> None:
    print("\n== #18 SSHHH_DATA_DIR 无测试模式时拒绝 ==")
    saved_dir = os.environ.get("SSHHH_DATA_DIR")
    saved_mode = os.environ.get("SSHHH_TEST_MODE")
    try:
        os.environ["SSHHH_DATA_DIR"] = str(_TMP / "elsewhere")
        os.environ.pop("SSHHH_TEST_MODE", None)
        code, out, err = run_cli(["status"])
        check("CLI 明确拒绝（退出码 3）", code == 3, f"{code} {out}{err}")
        check("报错说明测试模式", "SSHHH_TEST_MODE" in err, err)
        check("拒绝发生在任何数据访问之前", "数据目录" not in out, out)

        print("\n== #18 测试模式下覆盖生效 ==")
        os.environ["SSHHH_TEST_MODE"] = "1"
        code, out, err = run_cli(["status"])
        check("status 正常运行", code == 0, f"{out}{err}")
        check("数据目录就是覆盖值", str(_TMP) in out, out)
    finally:
        if saved_dir is not None:
            os.environ["SSHHH_DATA_DIR"] = saved_dir
        else:
            os.environ.pop("SSHHH_DATA_DIR", None)
        if saved_mode is not None:
            os.environ["SSHHH_TEST_MODE"] = saved_mode
        else:
            os.environ.pop("SSHHH_TEST_MODE", None)

    print("\n== #18 console_setup 入口同样拒绝 ==")
    worker = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "import console_setup; sys.exit(console_setup.main())"
    )
    env = dict(os.environ)
    env["SSHHH_DATA_DIR"] = str(_TMP / "elsewhere")
    env.pop("SSHHH_TEST_MODE", None)
    proc = subprocess.run(
        [sys.executable, "-I", "-c", worker, str(SCRIPTS)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=60, env=env,
    )
    check("向导入口退出码 3", proc.returncode == 3,
          f"{proc.stdout[-200:]}{proc.stderr[-200:]}")
    check("拒绝理由进 stderr", "SSHHH_TEST_MODE" in proc.stderr,
          proc.stderr[-300:])


# --------------------------------------------------------------------------
# #3 密钥管理：keygen / keyimport / keyshow（vault key:<host> 启用）
# --------------------------------------------------------------------------


def _audit_raw() -> str:
    try:
        return paths.audit_file().read_text(encoding="utf-8")
    except OSError:
        return ""


def _same_key_material(original: str, stored: str) -> bool:
    """比较导入前后的密钥材料：ed/ec 比公钥 blob，RSA 比 n/e。

    不能比 PEM 文本 —— 归一化本来就会改封装（这正是它的职责）。
    """
    import paramiko
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    from lib import sshkeys

    def _s(b: bytes) -> bytes:
        return len(b).to_bytes(4, "big") + b

    def _mpint(n: int) -> bytes:
        b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        if n == 0:
            b = b""
        return _s(b)

    try:
        key = serialization.load_pem_private_key(original.strip().encode(),
                                                 password=None)
        orig_kind = "crypto"
    except ValueError:
        # OpenSSH 容器输入：cryptography 读不了，原始侧也走 paramiko
        pk_orig = sshkeys.load_pkey(original)
        orig_kind = "paramiko"
    pk = sshkeys.load_pkey(stored)
    if orig_kind == "paramiko":
        # 输入本就是 paramiko 可读形态：归一化应原样保留（blob 逐字节一致）
        return (pk.get_name() == pk_orig.get_name()
                and pk.asbytes() == pk_orig.asbytes())
    if isinstance(key, ed25519.Ed25519PrivateKey):
        pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw)
        return (pk.get_name() == "ssh-ed25519"
                and pk.asbytes() == _s(b"ssh-ed25519") + _s(pub))
    if isinstance(key, ec.EllipticCurvePrivateKey):
        curve = {"secp256r1": "nistp256"}.get(key.curve.name, key.curve.name)
        point = key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return (pk.get_name() == f"ecdsa-sha2-{curve}"
                and pk.asbytes() == (_s(f"ecdsa-sha2-{curve}".encode())
                                     + _s(curve.encode()) + _s(point)))
    if isinstance(key, rsa.RSAPrivateKey):
        nums = key.public_key().public_numbers()
        blob = _s(b"ssh-rsa") + _mpint(nums.e) + _mpint(nums.n)
        return pk.get_name() == "ssh-rsa" and pk.asbytes() == blob
    return False


def test_key_management() -> None:
    from lib import sshkeys

    print("\n== #3 keygen：生成、入 vault、公钥可派生 ==")
    reset()
    setup_sealed_host()
    code, out, err = run_cli(["manage", "keygen", "prod"])
    check("keygen 退出码 0", code == 0, f"{out}{err}")
    check("输出含公钥行", "ssh-ed25519 " in out, out)
    check("输出含指纹", "SHA256:" in out, out)

    v = vault.open_vault()
    pem = v.get("key:prod")
    check("私钥入 vault key:<host>", bool(pem))
    check("names() 不含密钥条目",
          "prod" in v.names() and "key:prod" not in v.names(), str(v.names()))
    pk = sshkeys.load_pkey(pem)
    check("paramiko 能从内存加载生成的密钥", pk.get_name() == "ssh-ed25519")
    check("私钥材料不进输出", "BEGIN" not in out, out[:200])
    check("私钥材料不进审计", "BEGIN" not in _audit_raw())
    actions = [r.get("action") for r in audit.tail(5, include_internal=True)]
    check("审计记录 key.gen", "key.gen" in actions, str(actions))

    print("\n== #3 keygen：重复生成被拒，--force 轮换 ==")
    code, out, err = run_cli(["manage", "keygen", "prod"])
    check("已有密钥时退出码 3", code == 3, f"{out}{err}")
    old_fp = sshkeys.sha256_fingerprint(pem)
    code, out, err = run_cli(["manage", "keygen", "prod", "--force"])
    check("--force 轮换成功", code == 0, f"{out}{err}")
    pem2 = vault.open_vault().get("key:prod")
    check("轮换后私钥更换", pem2 != pem)
    check("轮换后指纹变化", sshkeys.sha256_fingerprint(pem2) != old_fp)

    print("\n== #3 keyimport：三种封装归一化后入库 ==")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    key_dir = Path(tempfile.mkdtemp(prefix="sshhh-keys-"))
    cases = {}
    cases["ed25519-pkcs8"] = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    cases["ecdsa-pkcs8"] = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    cases["rsa-pkcs1"] = rsa.generate_private_key(
        public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()
    # OpenSSH 容器是用户手里最常见的形态（ssh-keygen 产出），必须原样通过
    cases["ed25519-openssh"] = sshkeys.generate_ed25519_pem(comment="existing")

    for label, original in cases.items():
        src = key_dir / f"{label}.pem"
        src.write_text(original, encoding="utf-8")
        code, out, err = run_cli(["manage", "keyimport", "prod", str(src)])
        check(f"{label} 导入退出码 0", code == 0, f"{out}{err}")
        stored = vault.open_vault().get("key:prod")
        check(f"{label} 入库", bool(stored))
        try:
            sshkeys.load_pkey(stored)
            loadable = True
        except Exception:
            loadable = False
        check(f"{label} 归一化产物 paramiko 可加载", loadable)
        check(f"{label} 密钥材料一致（仅封装改变）",
              _same_key_material(original, stored))
    check("私钥材料不进审计", "BEGIN" not in _audit_raw())
    actions = [r.get("action") for r in audit.tail(10, include_internal=True)]
    check("审计记录 key.import", "key.import" in actions, str(actions))

    print("\n== #3 keyimport：拒绝与兜底 ==")
    enc_src = key_dir / "encrypted.pem"
    enc_src.write_text(rsa.generate_private_key(
        public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.BestAvailableEncryption(b"a-passphrase-1")).decode(),
        encoding="utf-8")
    code, out, err = run_cli(["manage", "keyimport", "prod", str(enc_src)])
    check("带口令私钥被拒（退出码 3）", code == 3, f"{out}{err}")
    check("报错给出口令处理指引", "口令" in err, err)

    junk = key_dir / "junk.pem"
    junk.write_text("PuTTY-User-Key-File-3: ssh-ed25519\nnot-a-pem\n",
                    encoding="utf-8")
    code, out, err = run_cli(["manage", "keyimport", "prod", str(junk)])
    check("非 PEM 文件被拒", code == 3, f"{out}{err}")

    missing = run_cli(["manage", "keyimport", "prod", str(key_dir / "nope.pem")])
    check("文件不存在退出码 3", missing[0] == 3, f"{missing[1]}{missing[2]}")

    print("\n== #3 keyimport：省略路径时用遗留 key_file ==")
    reset()
    setup_sealed_host()
    legacy_src = key_dir / "legacy.pem"
    legacy_src.write_text(cases["ed25519-pkcs8"], encoding="utf-8")
    store.upsert_host(store.Host(name="prod", host="127.0.0.1", user="root",
                                 key_file=str(legacy_src)))
    code, out, err = run_cli(["manage", "keyimport", "prod"])
    check("自动使用 key_file 路径", code == 0, f"{out}{err}")
    check("输出含 legacy 路径与删除提示",
          str(legacy_src) in out and "key_file" in out, out)

    print("\n== #3 keyshow：只显示公钥 ==")
    code, out, err = run_cli(["manage", "keyshow", "prod"])
    check("keyshow 退出码 0", code == 0, f"{out}{err}")
    check("输出含公钥行", "ssh-ed25519 " in out, out)
    check("输出含指纹", "SHA256:" in out, out)
    check("不含私钥材料", "BEGIN" not in out, out)
    code, out, err = run_cli(["manage", "keyshow", "ghost"])
    check("未知主机退出码 3", code == 3, f"{out}{err}")


# --------------------------------------------------------------------------
# #3 密钥优先登录与回落留痕（本地 SSH 服务端）
# --------------------------------------------------------------------------

_USER = "tester"
_SSH_PASSWORD = "Sup3r-Secret-Pw!<&>"


class _AuthServer(paramiko.ServerInterface):
    """公钥 + 密码双认证的迷你服务端：check_auth_publickey 比对授权公钥，
    相当于完成了一次真实的签名验证。"""

    def __init__(self, authorized_pub_b64: str) -> None:
        self.authorized = authorized_pub_b64
        self.event = threading.Event()
        self.command = b""

    def get_allowed_auths(self, username):
        return "publickey,password"

    def check_auth_publickey(self, username, key):
        if username == _USER and key.get_base64() == self.authorized:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        if username == _USER and password == _SSH_PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return (paramiko.OPEN_SUCCEEDED if kind == "session"
                else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def check_channel_exec_request(self, channel, command):
        self.command = command
        self.event.set()
        return True


def _handle_auth(transport, server) -> None:
    try:
        while True:
            chan = transport.accept(20)
            if chan is None:
                return
            if not server.event.wait(20):
                chan.close()
                return
            server.event.clear()
            chan.sendall(("(ran) "
                          + server.command.decode("utf-8", "replace") + "\n").encode())
            chan.send_exit_status(0)
            chan.close()
    except Exception:
        pass
    finally:
        try:
            transport.close()
        except Exception:
            pass


def _start_auth_server(authorized_pub_b64: str) -> tuple[int, threading.Event]:
    host_key = paramiko.RSAKey.generate(2048)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(20)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def loop() -> None:
        sock.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except (socket.timeout, OSError):
                continue
            t = paramiko.Transport(conn)
            t.add_server_key(host_key)
            srv = _AuthServer(authorized_pub_b64)
            try:
                t.start_server(server=srv)
            except Exception:
                t.close()
                continue
            threading.Thread(target=_handle_auth, args=(t, srv),
                             daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return port, stop


def _last_run_record() -> dict | None:
    for rec in reversed(audit.tail(10, include_internal=True)):
        if rec.get("action") == "run":
            return rec
    return None


def test_key_first_auth() -> None:
    from lib import sshkeys

    print("\n== #3 密钥优先：合法密钥直接通过 ==")
    reset()
    pem_auth = sshkeys.generate_ed25519_pem(comment="sshhh-test")
    authorized = sshkeys.load_pkey(pem_auth).get_base64()
    pem_bad = sshkeys.generate_ed25519_pem(comment="not-installed")
    port, stop = _start_auth_server(authorized)
    try:
        v = vault.Vault.create(paths.vault_file(), MASTER)
        store.upsert_host(store.Host(name="local", host="127.0.0.1",
                                     user=_USER, port=port))
        v.set("local", _SSH_PASSWORD)
        v.set("key:local", pem_auth)

        code, out, err = run_cli(["run", "local", "echo hi"])
        check("密钥认证 run 成功", code == 0, f"{out}{err}")
        rec = _last_run_record()
        check("审计 auth=key", rec is not None and rec.get("auth") == "key",
              str(rec))
        check("无回落标记", rec is not None and "fallback" not in rec, str(rec))
        check("没有回落提示", "回落" not in err, err)

        print("\n== #3 密钥被拒 → 回落密码，审计与 stderr 双留痕 ==")
        v.set("key:local", pem_bad)
        code, out, err = run_cli(["run", "local", "echo hi"])
        check("回落后 run 成功", code == 0, f"{out}{err}")
        rec = _last_run_record()
        check("审计 auth=password", rec is not None
              and rec.get("auth") == "password", str(rec))
        check("审计 fallback=key", rec is not None
              and rec.get("fallback") == "key", str(rec))
        check("stderr 有回落提示", "回落" in err, err)

        print("\n== #3 只有被拒密钥、没有密码 → 明确失败 ==")
        v.delete("local")
        code, out, err = run_cli(["run", "local", "echo hi"])
        check("退出码 4（网络/认证失败）", code == 4, f"{out}{err}")
        check("报错说明密钥被拒", "密钥认证被服务器拒绝" in err, err)
        rec = _last_run_record()
        check("失败记录 auth=key", rec is not None and rec.get("auth") == "key",
              str(rec))

        print("\n== #3 仅密码主机行为不变 ==")
        v.set("local", _SSH_PASSWORD)
        v.delete("key:local")
        code, out, err = run_cli(["run", "local", "echo hi"])
        check("密码认证 run 成功", code == 0, f"{out}{err}")
        rec = _last_run_record()
        check("审计 auth=password 且无 fallback",
              rec is not None and rec.get("auth") == "password"
              and "fallback" not in rec, str(rec))

        print("\n== #3 key_file 旁路封堵（#18）==")
        store.upsert_host(store.Host(name="legacy", host="127.0.0.1",
                                     user=_USER, port=port,
                                     key_file="~/.ssh/id_should_not_be_read"))
        code, out, err = run_cli(["run", "legacy", "echo hi"])
        check("仅 key_file 的主机退出码 3", code == 3, f"{out}{err}")
        check("报错指向 manage keyimport", "keyimport" in err, err)

        # key_file + 密码并存：密码照常可用（key_file 被忽略，不再从盘上读私钥）
        v.set("legacy", _SSH_PASSWORD)
        code, out, err = run_cli(["run", "legacy", "echo hi"])
        check("补了密码后 legacy 主机可用", code == 0, f"{out}{err}")
        rec = _last_run_record()
        check("legacy 用密码认证", rec is not None
              and rec.get("auth") == "password", str(rec))

        print("\n== #3 list 认证列反映 vault 状态 ==")
        v.set("key:local", pem_auth)
        # 有密码的 legacy 主机：key_file 惰性，正常显示密码
        store.upsert_host(store.Host(name="legacy2", host="127.0.0.1",
                                     user=_USER, port=port,
                                     key_file="~/.ssh/another"))
        code, out, err = run_cli(["list"])
        check("list 显示密钥（local 密钥+密码）", "密钥+密码" in out, out)
        check("list 标记无凭据的 legacy2", "key_file*" in out, out)
        check("list 提示迁移", "keyimport" in out, out)
    finally:
        stop.set()


def main() -> int:
    test_seal_roundtrip_and_tamper()
    test_unsealed_failclosed_and_reseal()
    test_enforcement_and_views()
    test_data_dir_gating()
    test_key_management()
    test_key_first_auth()

    print("\n" + "=" * 46)
    print(f"通过 {PASSED} 项，失败 {FAILED} 项")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
