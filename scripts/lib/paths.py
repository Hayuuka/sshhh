"""固定路径定义。

所有 agent 共用同一份数据目录 —— 这是「装多少份 skill 都只配一次密码」的关键。
路径写死在用户主目录下，与 skill 的安装位置无关，因此升级 / 重装 skill
不会覆盖配置。

环境变量 SSHHH_DATA_DIR 仅在显式测试模式（SSHHH_TEST_MODE=1）下生效（#18）：
它指到别处就能绕过基于路径的本地保护（put/get 的数据目录约束、指纹库与
签名文件的落点等）。正常使用不要设置。
"""

from __future__ import annotations

import os
from pathlib import Path

_DEFAULT_DATA_DIR = Path.home() / ".sshhh"

DATA_DIR_ENV = "SSHHH_DATA_DIR"
TEST_MODE_ENV = "SSHHH_TEST_MODE"


def data_dir() -> Path:
    """数据目录。

    `SSHHH_DATA_DIR` 只在 `SSHHH_TEST_MODE=1` 同时存在时生效；否则忽略该
    变量并回落默认目录。入口（sshhh.main / console_setup.main）会用
    `override_without_test_mode()` 检测这种组合并明确拒绝 —— 这里无声
    回落是为了让深层调用不至于拿到一个谁都没料到的目录。
    """
    override = os.environ.get(DATA_DIR_ENV)
    if override and os.environ.get(TEST_MODE_ENV) == "1":
        return Path(override)
    return _DEFAULT_DATA_DIR


def override_without_test_mode() -> str | None:
    """SSHHH_DATA_DIR 被设置但不在测试模式 → 返回拒绝理由；否则 None。

    拒绝而不是无声忽略（#18）：无声忽略会让「以为换了目录」的调用方把
    数据写到默认目录里，制造两份半重叠的配置，比明确报错难查得多。
    """
    if os.environ.get(DATA_DIR_ENV) and os.environ.get(TEST_MODE_ENV) != "1":
        return (
            f"{DATA_DIR_ENV} 只在测试模式（{TEST_MODE_ENV}=1）下生效："
            "它能改变凭据与保护机制的落点，正常使用不应设置。\n"
            "如果这确实是测试环境，请同时设置 SSHHH_TEST_MODE=1 后重试。"
        )
    return None


def vault_file() -> Path:
    return data_dir() / "vault.enc"


def hosts_file() -> Path:
    return data_dir() / "hosts.toml"


def audit_file() -> Path:
    return data_dir() / "audit.log"


def lock_file() -> Path:
    return data_dir() / ".lock"


def bootstrap_lock_file() -> Path:
    """运行环境自举专用的锁。

    与 `.lock` 分开：首次启动要建 venv + 装依赖，可能占用几分钟，不能让期间
    其它 agent 的读写操作陪着一起等（#10）。
    """
    return data_dir() / ".bootstrap"


def audit_lock_file() -> Path:
    """审计写入专用的锁（#47）。

    与 `.lock` 分开：审计写入嵌在 vault.open 这类不该等锁的读路径里
    （vault._audit_open），若与 hosts.toml / vault 共用一把锁，任何配置
    写入都会让读路径陪着等。审计锁只串行化「轮转 + 追加」这一小段，
    临界区毫秒级。
    """
    return data_dir() / ".audit"


def no_window_marker() -> Path:
    """标记文件：这个环境里弹窗撑不住（命令一结束就被宿主回收）。

    出现这个文件说明之前交接出去的窗口已经死了、配置却没完成，
    之后不再尝试弹窗，直接引导用户在自己的终端里配置。
    """
    return data_dir() / ".no-window"


def venv_dir() -> Path:
    return data_dir() / "venv"


def venv_python() -> Path:
    v = venv_dir()
    if os.name == "nt":
        return v / "Scripts" / "python.exe"
    return v / "bin" / "python"


def known_hosts_file() -> Path:
    return data_dir() / "known_hosts"


def ensure_data_dir() -> Path:
    d = data_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d


KEYRING_SERVICE = "sshhh"

# 配置窗口等待用户输入的默认上限（秒）
DEFAULT_SETUP_TIMEOUT = 180
MIN_SETUP_TIMEOUT = 30
MAX_SETUP_TIMEOUT = 600
