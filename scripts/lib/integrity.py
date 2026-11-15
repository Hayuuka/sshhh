"""hosts.toml 的完整性签名（#18）。

hosts.toml 在 agent 可写的路径上：删掉 `[hosts.x.policy]` 段就能永久豁免
命令策略，追加一行就能把认证指向任意路径（TM-B3）。本模块给清单加一把
HMAC-SHA256 签名，密钥从主密码派生 —— 把「改策略」从编辑一个文本文件
升级为「解开密码库 + import 内部模块」，落在 README 已声明的残余风险线上
（同 UID 进程仍然拦得住自己，定性依旧是防手滑，不是边界）。

签名存放在 hosts.toml 自己的 `[sshhh_integrity]` 段。签名对象是「去掉该段
之后、用 tomli-w 重新序列化」的规范形式：

- 注释与排版不参与签名 —— 手编注释、调整空行不会弄坏签名
- 任何字段值的改动都会让签名失配 —— 这正是要拦的

读侧（store.load）：密码库解锁后验签，失败一律 fail-closed，拒绝连接并
明确报错；密码库没解锁（list / status / policy 这类不碰策略的只读路径）
时跳过验签，让用户还能用它们检查被改过的文件。

写侧（store._write_doc）：原有文件带着**有效**签名才重签 —— 向导加主机、
迁移都会自动续签；没签名的旧文件（升级前遗留或被改过）写完仍然不签名，
防止「一次普通写入就把被篡改的内容洗白」。
"""

from __future__ import annotations

import hashlib
import hmac

# 签名段名与方案标识。方案带版本号：将来换算法时旧文件能被识别出来，
# 而不是拿着新算法去验旧签名、得到一场谁也看不懂的失败。
SECTION = "sshhh_integrity"
SCHEME = "hmac-sha256-v1"

# 签名密钥不直接复用 vault 的 AES 密钥，而是从它派生一把独立的 MAC 密钥：
# 同一把密钥跨 AES-GCM 和 HMAC 两种算法使用没有已知问题，但分开派生后
# 两把钥匙可以独立轮换，也不必在两者之间做任何「确保不撞用例」的论证。
_LABEL = b"sshhh/hosts-integrity/v1"

# 从 Vault.open / Vault.create 绑定；进程内有效（进程退出即消失，与
# 解密出的明文密码同一生命周期）。
_mac_key: bytes | None = None


def set_vault_key(vault_key: bytes) -> None:
    """绑定签名密钥：从解开密码库得到的 AES 密钥派生。

    由 vault 模块在成功解密后调用。密码库没解开（或解开失败）时不会
    被调用，验签随之跳过 —— 只读视图不受影响，强制路径必然已解锁。
    """
    global _mac_key
    _mac_key = hmac.new(vault_key, _LABEL, hashlib.sha256).digest()


def mac_key() -> bytes | None:
    return _mac_key


def _canonical(doc: dict) -> str:
    """去掉签名段后整份规范序列化。tomli_w 的输出是确定性的：同一份
    解析结果反复序列化得到完全相同的字节，这是签名可复算的前提。"""
    import tomli_w

    body = {k: v for k, v in doc.items() if k != SECTION}
    return tomli_w.dumps(body)


def compute_mac(doc: dict, key: bytes) -> str:
    return hmac.new(key, _canonical(doc).encode("utf-8"), hashlib.sha256).hexdigest()


def seal_doc(doc: dict, key: bytes) -> dict:
    """给文档签名：剥掉旧签名段、计算、写回，返回新的文档。"""
    body = {k: v for k, v in doc.items() if k != SECTION}
    body[SECTION] = {"scheme": SCHEME, "mac": compute_mac(body, key)}
    return body


def verify_doc(doc: dict, key: bytes) -> str | None:
    """验签。返回 None 表示通过，否则返回给人看（也会转告用户）的原因。

    空清单不要求签名：里面没有主机就没有可保护的东西，且首台主机的
    写入路径是「创建时即签名」，空清单无签名只会短暂存在。
    """
    body = {k: v for k, v in doc.items() if k != SECTION}
    if not body.get("hosts"):
        return None
    seal = doc.get(SECTION)
    if not isinstance(seal, dict) or not seal:
        return "hosts.toml 没有完整性签名（升级前的旧文件，或签名段被删除）"
    if seal.get("scheme") != SCHEME:
        return (f"hosts.toml 的签名方案不受支持：{seal.get('scheme')!r}"
                "（签名段被改动过，或来自其它版本的程序）")
    expected = compute_mac(body, key)
    actual = str(seal.get("mac") or "")
    if not hmac.compare_digest(expected, actual):
        return "hosts.toml 完整性签名不匹配（签名之后文件被改动过）"
    return None
