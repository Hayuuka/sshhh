"""加密保险库：AES-GCM + scrypt，主密码存系统钥匙串。

与路径无关的纯逻辑，数据位置由 paths 模块决定。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets as _secrets
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import paths
from .fsutil import read_text
from .lock import data_lock

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

VAULT_VERSION = 1

# AAD 的演进：旧版用常量 "sshhh-vault"（S7 评审项）。常量 AAD 不绑定头部，
# 将来字段变化时密文仍能被「错误格式」解开，格式混淆没有防线。
# 新版把头部静态部分（v + kdf 参数）以 canonical JSON 参与 GCM 认证；
# 打开旧文件时先试新 AAD、再回落旧常量，成功后下次落盘自动升级。
_LEGACY_AAD = b"sshhh-vault"


def _canonical_aad(header: dict) -> bytes:
    static = {"v": header.get("v"), "kdf": header.get("kdf")}
    return json.dumps(static, sort_keys=True, separators=(",", ":")).encode("utf-8")

_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LEN = 32


class VaultError(Exception):
    """保险库错误。消息中不得包含密码。"""


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _derive(master: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=_KEY_LEN, n=n, r=r, p=p).derive(
        master.encode("utf-8")
    )


# --------------------------------------------------------------------------
# 系统钥匙串
# --------------------------------------------------------------------------


def _keyring():
    try:
        import keyring

        backend = keyring.get_keyring()
        if backend.__class__.__module__.startswith("keyring.backends.fail"):
            return None
        if not getattr(backend, "priority", 0):
            return None
        return keyring
    except Exception:
        return None


def keyring_available() -> bool:
    return _keyring() is not None


def _keyring_ids(vault_path: Path, service: str | None = None) -> tuple[str, str]:
    digest = hashlib.sha256(str(vault_path.resolve()).encode()).hexdigest()[:16]
    return f"{service or paths.KEYRING_SERVICE}:master", digest


def keyring_load(vault_path: Path, service: str | None = None) -> str | None:
    kr = _keyring()
    if not kr:
        return None
    name, user = _keyring_ids(vault_path, service)
    try:
        return kr.get_password(name, user)
    except Exception:
        return None


def keyring_save(vault_path: Path, master: str,
                 service: str | None = None) -> bool:
    kr = _keyring()
    if not kr:
        return False
    name, user = _keyring_ids(vault_path, service)
    try:
        kr.set_password(name, user, master)
        return True
    except Exception:
        return False


def keyring_forget(vault_path: Path, service: str | None = None) -> None:
    kr = _keyring()
    if not kr:
        return
    name, user = _keyring_ids(vault_path, service)
    try:
        kr.delete_password(name, user)
    except Exception:
        pass


# --------------------------------------------------------------------------
# gpg 加密文件后端（headless Linux 一等公民，#19）
#
# 无 Secret Service 的服务器 / 容器上没有钥匙串，主密码无处安放：文档兜底
# SSHHH_MASTER 恰是 agent 能 printenv 读到的，等于放弃安全模型。这里给
# headless 一个不进环境变量的选择：主密码用本机 gpg 私钥加密后存
# ~/.sshhh/master.gpg，解密走 gpg-agent —— 与 pass（gpg）同一套机制。
#
# 定性（如实声明）：gpg 私钥对同 UID 进程同样可用，这仍是 OS 边界内的
# 「不被顺手读到」而非「防同用户恶意进程」；vault.open 的解密留痕不变。
# --------------------------------------------------------------------------

GPG_FILE_NAME = "master.gpg"


def _gpg() -> str | None:
    return shutil.which("gpg") or shutil.which("gpg2")


def gpg_available() -> bool:
    return _gpg() is not None


def gpg_file(vault_path: Path) -> Path:
    return vault_path.parent / GPG_FILE_NAME


def _first_secret_fpr(text: str) -> str | None:
    """从 gpg --with-colons 输出里取第一把**有私钥**的键的指纹。

    sec 行后面跟着 fpr 行（第 10 列是完整指纹）。没有私钥的机器解不开，
    只有公钥没用。
    """
    seen_sec = False
    for line in text.splitlines():
        fields = line.split(":")
        if fields[0] == "sec":
            seen_sec = True
        elif fields[0] == "fpr" and seen_sec and len(fields) > 9 and fields[9]:
            return fields[9]
    return None


def _gpg_recipient(gpg: str) -> str | None:
    try:
        proc = subprocess.run(
            [gpg, "--batch", "--list-secret-keys", "--with-colons"],
            capture_output=True, timeout=15,
            creationflags=_NO_WINDOW,
        )
        if proc.returncode != 0:
            return None
        return _first_secret_fpr(proc.stdout.decode("utf-8", "replace"))
    except Exception:
        return None


def gpg_load_master(vault_path: Path) -> str | None:
    """解密 master.gpg。gpg 缺席、私钥不可用、文件不存在都返回 None。"""
    gpg = _gpg()
    f = gpg_file(vault_path)
    if not gpg or not f.exists():
        return None
    try:
        proc = subprocess.run(
            [gpg, "--batch", "--quiet", "-d", str(f)],
            capture_output=True, timeout=30,
            creationflags=_NO_WINDOW,
        )
        if proc.returncode != 0:
            return None
        text = proc.stdout.decode("utf-8", "replace").strip()
        return text or None
    except Exception:
        return None


def gpg_save_master(vault_path: Path, master: str) -> bool:
    """把主密码加密到 master.gpg。失败返回 False（调用方继续兜底）。"""
    gpg = _gpg()
    if not gpg or not master:
        return False
    recipient = _gpg_recipient(gpg)
    if not recipient:
        return False
    f = gpg_file(vault_path)
    try:
        proc = subprocess.run(
            [gpg, "--batch", "--yes", "--trust-model", "always", "-e",
             "-r", recipient, "-o", str(f)],
            input=(master + "\n").encode("utf-8"),
            capture_output=True, timeout=30,
            creationflags=_NO_WINDOW,
        )
        if proc.returncode != 0:
            return False
        try:
            os.chmod(f, 0o600)
        except OSError:
            pass
        _harden(f)
        return True
    except Exception:
        return False


def save_master_auto(vault_path: Path, master: str) -> str | None:
    """存主密码：优先系统钥匙串，其次 gpg 加密文件。

    返回用的后端名（"keyring" / "gpg"），全失败返回 None —— 调用方据此
    提示用户（还剩 SSHHH_MASTER 环境变量兜底，但 agent 可读，只做最后手段）。
    """
    if keyring_save(vault_path, master):
        return "keyring"
    if gpg_save_master(vault_path, master):
        return "gpg"
    return None


# --------------------------------------------------------------------------
# 保险库
# --------------------------------------------------------------------------


# 审计里保留几个命令行参数。整串 sys.argv 落盘等于把「调用方随手写在命令里的
# 秘密」也落盘 —— `run prod --stdin S3cret mysql -pS3cret` 会原样进 audit.log，
# 而 redactor 只认得主密码和库里已有的值（#29）。前两个参数足够定位调用方式。
_ARGV_KEEP = 2


def _audit_open(path: Path, master: str | None,
                values: Iterable[object] = ()) -> None:
    """记录一次成功的解密。

    同用户的进程可以绕过 sshhh.py 直接调本模块，这是操作系统级边界，
    代码层面堵不住。但可以让它留下痕迹：pid、可执行文件、工作目录、命令行
    前缀写进 audit.log，事后能查到「是谁在什么时候解开了密码库」。

    落盘前用与命令输出同一套 redactor 过一遍：主密码、库里已有的密码、
    以及任何 `password=...` 形态的片段都替换成 [REDACTED]。审计日志本身
    不能成为新的泄漏点。
    """
    try:
        from . import audit
        from .redact import Redactor

        argv_head = " ".join(sys.argv[:_ARGV_KEEP])
        text = (f"pid={os.getpid()} exe={os.path.basename(sys.executable)} "
                f"cwd={os.getcwd()} argv={argv_head}")
        redactor = Redactor([v for v in values if isinstance(v, str)])
        if master:
            redactor.add(master)
        audit.write("vault.open", command=redactor.clean(text))
    except Exception:  # noqa: BLE001
        # 审计写不进去也不能让解密失败
        pass


class Vault:
    def __init__(self, path: Path):
        self.path = path
        self._key: bytes | None = None
        self._header: dict | None = None
        self._data: dict[str, str] = {}
        # 旧常量 AAD 解开的文件在下次写盘时升级为 canonical AAD
        self._legacy_aad = False

    # -- 生命周期 ------------------------------------------------------

    @classmethod
    def create(cls, path: Path, master: str) -> "Vault":
        if path.exists():
            raise VaultError(f"保险库已存在：{path}")
        v = cls(path)
        salt = _secrets.token_bytes(16)
        v._header = {
            "v": VAULT_VERSION,
            "kdf": {
                "name": "scrypt",
                "salt": _b64e(salt),
                "n": _SCRYPT_N,
                "r": _SCRYPT_R,
                "p": _SCRYPT_P,
            },
        }
        v._key = _derive(master, salt, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
        v._data = {}
        v._flush()
        from . import integrity
        integrity.set_vault_key(v._key)
        return v

    @classmethod
    def open(cls, path: Path, master: str | None = None,
             allow_keyring: bool = True) -> "Vault":
        if not path.exists():
            raise VaultError("保险库不存在")
        try:
            # 读走 fsutil 的短重试（#45）：Windows 上 _flush 的原子替换
            # 落盘瞬间，并发读 open() 可能拿到瞬时共享冲突 —— 裸 read_text
            # 会把它误报成「保险库文件损坏」，触发莫名其妙的解锁弹窗流程。
            # hosts.toml / known_hosts 早已如此，vault 是三个数据文件里
            # 唯一漏掉的。
            header = json.loads(read_text(path))
        except (OSError, json.JSONDecodeError) as exc:
            raise VaultError(f"保险库文件损坏：{exc}") from None
        if header.get("v") != VAULT_VERSION:
            raise VaultError("保险库版本不受支持")

        v = cls(path)
        v._header = header
        kdf = header["kdf"]
        salt = _b64d(kdf["salt"])
        n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])

        candidates: list[str] = []
        if master:
            candidates.append(master)
        else:
            env = os.environ.get("SSHHH_MASTER")
            if env:
                candidates.append(env)
            if allow_keyring:
                cached = keyring_load(path)
                if cached:
                    candidates.append(cached)
                # 无钥匙串的 headless 环境（#19）：gpg 加密文件兜在钥匙串后面
                cached = gpg_load_master(path)
                if cached:
                    candidates.append(cached)

        for cand in candidates:
            v._key = _derive(cand, salt, n, r, p)
            try:
                v._data = v._decrypt(_canonical_aad(header))
                v._legacy_aad = False
            except InvalidTag:
                # 旧版文件用常量 AAD 加密；能解开说明主密码没错，
                # 只是格式老 —— 标记后由 _flush 升级（S7）
                try:
                    v._data = v._decrypt(_LEGACY_AAD)
                except InvalidTag:
                    continue
                v._legacy_aad = True
            _audit_open(path, cand, v._data.values())
            # 绑定 hosts.toml 完整性签名的 MAC 密钥（#18）：签名随密码库
            # 解锁而生效，强制路径（run / test / put / get / harden）先解锁
            # 后验签，锁定时只读视图仍可用
            from . import integrity
            integrity.set_vault_key(v._key)
            return v

        raise VaultError("主密码错误或钥匙串中没有可用的主密码")

    # -- 内部 ----------------------------------------------------------

    def _decrypt(self, aad: bytes) -> dict[str, str]:
        assert self._key is not None and self._header is not None
        nonce = _b64d(self._header["nonce"])
        ct = _b64d(self._header["ct"])
        plain = AESGCM(self._key).decrypt(nonce, ct, aad)
        return json.loads(plain.decode("utf-8"))

    def _flush(self) -> None:
        assert self._key is not None and self._header is not None
        nonce = _secrets.token_bytes(12)
        plain = json.dumps(self._data, ensure_ascii=False).encode("utf-8")
        aad = _canonical_aad(self._header)
        ct = AESGCM(self._key).encrypt(nonce, plain, aad)
        out = dict(self._header)
        # 头部不写条目名：谁能拷走 vault.enc，谁就能枚举「这台机器上有哪些凭据」
        # （值解不开，清单却一目了然）。旧版本写过这个字段，顺手清掉。
        out.pop("entries", None)
        out["nonce"] = _b64e(nonce)
        out["ct"] = _b64e(ct)

        # 落盘走 fsutil 的原子写：mkstemp 临时名唯一，并发写不再互踩固定
        # 的 vault.tmp（S8）；tmp + os.replace 保证并发读不拿到半截文件
        from .fsutil import atomic_write_text

        atomic_write_text(self.path, json.dumps(out, ensure_ascii=False, indent=2))
        self._legacy_aad = False
        _harden(self.path)

    # -- 对外 ----------------------------------------------------------

    def get(self, name: str) -> str | None:
        return self._data.get(name)

    def set(self, name: str, value: str) -> None:
        self._data[name] = value
        self._flush()

    def delete(self, name: str) -> bool:
        if name in self._data:
            del self._data[name]
            self._flush()
            return True
        return False

    def names(self) -> list[str]:
        """密码条目名（不含 key: 私钥命名空间）。

        `key:<host>` 命名空间预留给 P2 的密钥认证（#37）：与密码条目隔离，
        避免「按主机名查密码」的调用方误把私钥材料当密码取走。
        """
        return sorted(n for n in self._data if not n.startswith("key:"))

    def key_names(self) -> list[str]:
        """私钥条目名（key:<host>）。使用侧随 P2 密钥认证启用。"""
        return sorted(n for n in self._data if n.startswith("key:"))

    def values(self) -> list[str]:
        """全部明文值。供 Redactor 用 vault 全量构造（#34 I9）：
        A 机的密码出现在 B 机的输出里时同样要被替换。"""
        return list(self._data.values())

    def rekey(self, new_master: str) -> None:
        assert self._header is not None
        salt = _secrets.token_bytes(16)
        self._header["kdf"] = {
            "name": "scrypt",
            "salt": _b64e(salt),
            "n": _SCRYPT_N,
            "r": _SCRYPT_R,
            "p": _SCRYPT_P,
        }
        self._key = _derive(new_master, salt, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
        # 换了主密码，签名密钥随之更换；旧签名会失效，需重新 reseal（#18）
        from . import integrity
        integrity.set_vault_key(self._key)
        self._flush()


def _harden(path: Path) -> None:
    try:
        if os.name == "nt":
            import subprocess

            who = os.environ.get("USERNAME", "")
            if not who:
                return
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{who}:F"],
                capture_output=True,
                timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        else:
            path.chmod(0o600)
    except Exception:
        pass


# --------------------------------------------------------------------------
# 高层封装（带锁）
# --------------------------------------------------------------------------


def open_vault(master: str | None = None, allow_keyring: bool = True) -> Vault:
    return Vault.open(paths.vault_file(), master=master, allow_keyring=allow_keyring)


def write_secret(name: str, value: str) -> None:
    """在锁保护下写入单个密码（供控制台窗口调用）。"""
    with data_lock():
        vault = open_vault()
        vault.set(name, value)


def prompt_master(label: str = "主密码", confirm: bool = False) -> str:
    import getpass

    if not sys.stdin.isatty():
        raise VaultError(f"需要输入{label}，但当前不是交互终端")
    pw = getpass.getpass(f"{label}: ")
    if not pw:
        raise VaultError(f"{label}不能为空")
    if confirm and getpass.getpass(f"再次输入{label}: ") != pw:
        raise VaultError("两次输入不一致")
    return pw
