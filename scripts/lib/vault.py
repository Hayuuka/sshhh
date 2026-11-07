"""加密保险库：AES-GCM + scrypt，主密码存系统钥匙串。

与路径无关的纯逻辑，数据位置由 paths 模块决定。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets as _secrets
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import paths
from .lock import data_lock

VAULT_VERSION = 1
_AAD = b"sshhh-vault"

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
# 保险库
# --------------------------------------------------------------------------


class Vault:
    def __init__(self, path: Path):
        self.path = path
        self._key: bytes | None = None
        self._header: dict | None = None
        self._data: dict[str, str] = {}

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
        return v

    @classmethod
    def open(cls, path: Path, master: str | None = None,
             allow_keyring: bool = True) -> "Vault":
        if not path.exists():
            raise VaultError("保险库不存在")
        try:
            header = json.loads(path.read_text(encoding="utf-8"))
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

        for cand in candidates:
            try:
                v._key = _derive(cand, salt, n, r, p)
                v._data = v._decrypt()
                return v
            except InvalidTag:
                continue

        raise VaultError("主密码错误或钥匙串中没有可用的主密码")

    # -- 内部 ----------------------------------------------------------

    def _decrypt(self) -> dict[str, str]:
        assert self._key is not None and self._header is not None
        nonce = _b64d(self._header["nonce"])
        ct = _b64d(self._header["ct"])
        plain = AESGCM(self._key).decrypt(nonce, ct, _AAD)
        return json.loads(plain.decode("utf-8"))

    def _flush(self) -> None:
        assert self._key is not None and self._header is not None
        nonce = _secrets.token_bytes(12)
        plain = json.dumps(self._data, ensure_ascii=False).encode("utf-8")
        ct = AESGCM(self._key).encrypt(nonce, plain, _AAD)
        out = dict(self._header)
        out["entries"] = sorted(self._data)
        out["nonce"] = _b64e(nonce)
        out["ct"] = _b64e(ct)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)
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
        return sorted(self._data)

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
