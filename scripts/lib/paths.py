"""固定路径定义。

所有 agent 共用同一份数据目录 —— 这是「装多少份 skill 都只配一次密码」的关键。
路径写死在用户主目录下，与 skill 的安装位置无关，因此升级 / 重装 skill
不会覆盖配置。

环境变量 SSHHH_DATA_DIR 仅用于测试隔离，正常使用不要设置。
"""

from __future__ import annotations

import os
from pathlib import Path

_DEFAULT_DATA_DIR = Path.home() / ".sshhh"


def data_dir() -> Path:
    override = os.environ.get("SSHHH_DATA_DIR")
    return Path(override) if override else _DEFAULT_DATA_DIR


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
