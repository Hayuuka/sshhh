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
