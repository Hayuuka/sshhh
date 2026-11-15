"""SSH 密钥的生成、归一化与内存加载（#3 基线部分）。

设计约束（docs/DESIGN.md §2，评审 F6/Q5）：

- **私钥只以密文存在 vault 内**（`key:<host>` 条目）。运行时从内存加载
  （`paramiko.Ed25519Key.from_private_key(StringIO(pem))`），进程退出即消失。
  明文私钥落盘 = 把加密凭据降级成明文凭据，本模块的任何函数都不写盘。
- 密钥材料不进 argv、日志、审计 —— 调用方拿到返回值后只允许交给 vault 或
  paramiko。

paramiko 5.x 从内存字符串加载时只认「传统」封装：Ed25519 必须 OpenSSH
容器格式，RSA 必须 PKCS1，ECDSA 必须 SEC1。cryptography 生成的 Ed25519 /
ECDSA 默认是 PKCS8，paramiko 读不了 —— 所以本模块负责两件事：

1. `generate_ed25519_pem()`：直接产出 paramiko 可读的 OpenSSH 容器
   （无口令、kdf=none，结构按 OpenSSH 私钥容器规范手写）。
2. `normalize_pem()`：导入任意 PEM 时用 cryptography 解析，再以 paramiko
   可读的格式重新序列化 —— 导入时校验 + 归一，运行时（transport）拿到的
   一定是可以直接加载的形态。

带口令的私钥一律拒绝导入：解口令属于用户本机的操作，sshhh 不代做。
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import textwrap

import paramiko

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


class SSHKeyError(Exception):
    """密钥处理错误。消息可转告用户，不得包含密钥材料。"""


_PASSPHRASE_MSG = (
    "这把私钥带口令加密，sshhh 不代解口令。请在你的终端先用 "
    "`ssh-keygen -p -f 私钥文件` 移除口令（输旧口令、新口令留空回车）"
    "后再导入"
)


def _ssh_string(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def _ed25519_openssh_pem(seed: bytes, pub: bytes, comment: str = "") -> str:
    """把 Ed25519 私钥写成无口令的 OpenSSH 容器 PEM。

    容器结构（OpenSSH 私钥格式）：
      b"openssh-key-v1\\0" + string(cipher) + string(kdf) + string(kdfoptions)
      + uint32(1) + string(pubkey blob) + string(私钥区)
    私钥区：checkint ×2 + string(keytype) + string(pub) + string(seed+pub)
      + string(comment) + 1,2,3… padding 到 8 字节对齐。
    """
    checkint = os.urandom(4)
    pub_blob = _ssh_string(b"ssh-ed25519") + _ssh_string(pub)
    section = (checkint + checkint
               + _ssh_string(b"ssh-ed25519") + _ssh_string(pub)
               + _ssh_string(seed + pub) + _ssh_string(comment.encode("utf-8")))
    pad = 1
    while len(section) % 8:
        section += bytes([pad])
        pad += 1
    container = (b"openssh-key-v1\x00" + _ssh_string(b"none")
                 + _ssh_string(b"none") + _ssh_string(b"")
                 + (1).to_bytes(4, "big") + _ssh_string(pub_blob)
                 + _ssh_string(section))
    b64 = base64.b64encode(container).decode("ascii")
    body = "\n".join(textwrap.wrap(b64, 70))
    return ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + body
            + "\n-----END OPENSSH PRIVATE KEY-----\n")


def generate_ed25519_pem(comment: str = "") -> str:
    """生成新的 Ed25519 密钥对，返回 paramiko 可读的私钥 PEM（不落盘）。"""
    key = ed25519.Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw,
                             serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
    return _ed25519_openssh_pem(seed, pub, comment)


def normalize_pem(pem: str) -> str:
    """解析任意 PEM 私钥，重新序列化为 paramiko 内存加载可读的格式。

    接受 PKCS8 / PKCS1 / SEC1 / OpenSSH 容器；带口令的私钥拒绝（错误信息
    给出用户侧的处理办法）。解析失败抛 SSHKeyError。

    注意（版本行为）：cryptography 50.x 的 load_pem_private_key 不再解析
    OpenSSH 容器（paramiko 与 sshd 都认它）。这类输入只可能是 paramiko
    可读的三种传统形态之一 —— 让 paramiko 验证后原样收下即可。
    """
    text = pem.strip()
    data = text.encode("utf-8")
    if not data.startswith(b"-----BEGIN"):
        raise SSHKeyError("这不是 PEM 格式的私钥文件（缺少 -----BEGIN 头）")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except TypeError:
        raise SSHKeyError(_PASSPHRASE_MSG) from None
    except ValueError:
        # cryptography 读不了（OpenSSH 容器为主）：退回 paramiko 判定
        try:
            load_pkey(text)
        except SSHKeyError as exc:
            if "口令" in str(exc):
                raise SSHKeyError(_PASSPHRASE_MSG) from None
            raise SSHKeyError(f"私钥解析失败：paramiko 与 cryptography 都读不了这把私钥"
                              "（支持 OpenSSH / PKCS8 / PKCS1 / SEC1 格式的 PEM）") from None
        return text + "\n"

    if isinstance(key, ed25519.Ed25519PrivateKey):
        seed = key.private_bytes(serialization.Encoding.Raw,
                                 serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
        pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw)
        return _ed25519_openssh_pem(seed, pub)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        # paramiko 只认 SEC1（BEGIN EC PRIVATE KEY）
        return key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.TraditionalOpenSSL,
                                 serialization.NoEncryption()).decode("ascii")
    if isinstance(key, rsa.RSAPrivateKey):
        # paramiko 只认 PKCS1（BEGIN RSA PRIVATE KEY）
        return key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.TraditionalOpenSSL,
                                 serialization.NoEncryption()).decode("ascii")
    raise SSHKeyError(f"暂不支持这类私钥：{type(key).__name__}")


def load_pkey(pem: str) -> paramiko.PKey:
    """从内存字符串加载私钥（不碰文件系统）。失败抛 SSHKeyError。"""
    errors = []
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(pem))
        except paramiko.PasswordRequiredException:
            raise SSHKeyError(_PASSPHRASE_MSG) from None
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{cls.__name__}: {exc}")
    raise SSHKeyError("私钥加载失败（" + "; ".join(errors) + ")")


def public_key_line(pem: str, comment: str = "") -> str:
    """从私钥 PEM 派生一行可放进 authorized_keys 的公钥。

    只含公开材料 —— 这是唯一允许打印到终端/文档的密钥形态。
    """
    pk = load_pkey(pem)
    line = f"{pk.get_name()} {pk.get_base64()}"
    if comment:
        line += f" {comment}"
    return line


def sha256_fingerprint(pem: str) -> str:
    """OpenSSH 风格 SHA256 指纹（无填充），与 `ssh-keygen -lf` 一致。"""
    pk = load_pkey(pem)
    digest = hashlib.sha256(pk.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
