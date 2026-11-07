"""主机清单（hosts.toml）。

只存连接信息，**永不存密码** —— 密码一律在 vault.enc 里按主机名索引。
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import paths

HEADER = """\
# sshhh 主机清单 —— 由程序自动维护，也可以手写
#
# 这里没有密码字段，密码在 vault.enc 里，用 sshhh setpass <名称> 录入。
# 手动加主机后不必再做什么，第一次执行时会自动要求补充密码。

"""

_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")


class StoreError(Exception):
    pass


@dataclass
class Policy:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)

    def check(self, command: str) -> str | None:
        for pat in self.deny:
            if re.search(pat, command):
                return f"命中禁止规则 /{pat}/"
        if self.allow:
            for pat in self.allow:
                if re.search(pat, command):
                    return None
            return "未命中任何允许规则（该主机处于白名单模式）"
        return None

    @property
    def active(self) -> bool:
        return bool(self.allow or self.deny)


@dataclass
class Host:
    name: str
    host: str
    user: str
    port: int = 22
    description: str = ""
    sudo: bool = False
    key_file: str | None = None
    policy: Policy = field(default_factory=Policy)


@dataclass
class Settings:
    connect_timeout: float = 15.0
    command_timeout: float = 300.0

    @property
    def known_hosts(self) -> Path:
        return paths.known_hosts_file()


def load() -> dict[str, Host]:
    path = paths.hosts_file()
    if not path.exists():
        return {}
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise StoreError(f"hosts.toml 解析失败：{exc}") from None
    except OSError as exc:
        raise StoreError(f"hosts.toml 读取失败：{exc}") from None

    hosts: dict[str, Host] = {}
    for name, item in (raw.get("hosts") or {}).items():
        if not isinstance(item, dict):
            continue
        if not item.get("host") or not item.get("user"):
            continue
        pol = item.get("policy") or {}
        hosts[name] = Host(
            name=name,
            host=str(item["host"]),
            user=str(item["user"]),
            port=int(item.get("port", 22)),
            description=str(item.get("description", "")),
            sudo=bool(item.get("sudo", False)),
            key_file=item.get("key_file") or None,
            policy=Policy(
                allow=[str(x) for x in (pol.get("allow") or [])],
                deny=[str(x) for x in (pol.get("deny") or [])],
            ),
        )
    return hosts


def get(name: str) -> Host | None:
    return load().get(name)


def _section_index(text: str, name: str) -> tuple[int, int] | None:
    """返回 [hosts.name] 段的 (起始行, 结束行)。"""
    lines = text.splitlines()
    start = None
    for idx, line in enumerate(lines):
        m = _SECTION_RE.match(line)
        if not m:
            continue
        parts = [p.strip() for p in m.group(1).split(".")]
        if len(parts) >= 2 and parts[0] == "hosts" and parts[1] == name:
            if start is None:
                start = idx
        elif start is not None:
            return start, idx
    if start is None:
        return None
    return start, len(lines)


def upsert_host(host: Host) -> None:
    """新增或更新一台主机（保留文件中的其它内容与注释）。"""
    path = paths.hosts_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    text = path.read_text(encoding="utf-8") if path.exists() else HEADER

    block = [f"[hosts.{host.name}]"]
    if host.description:
        block.append(f'description = "{_esc(host.description)}"')
    block.append(f'host = "{_esc(host.host)}"')
    block.append(f"port = {host.port}")
    block.append(f'user = "{_esc(host.user)}"')
    if host.sudo:
        block.append("sudo = true")
    if host.key_file:
        block.append(f'key_file = "{_esc(host.key_file)}"')

    span = _section_index(text, host.name)
    if span is None:
        text = text.rstrip("\n") + "\n\n" + "\n".join(block) + "\n"
    else:
        start, end = span
        lines = text.splitlines()
        # 只替换主段，保留后面的 [hosts.xxx.policy] 子段
        section_end = start + 1
        while section_end < end:
            m = _SECTION_RE.match(lines[section_end])
            if m:
                break
            section_end += 1
        new_lines = lines[:start] + block + [""] + lines[section_end:]
        text = "\n".join(new_lines).rstrip("\n") + "\n"

    path.write_text(text, encoding="utf-8")


def remove_host(name: str) -> bool:
    path = paths.hosts_file()
    if not path.exists():
        return False
    text = path.read_text(encoding="utf-8")
    span = _section_index(text, name)
    if span is None:
        return False
    start, end = span
    lines = text.splitlines()
    del lines[start:end]
    path.write_text("\n".join(lines).rstrip("\n") + "\n", encoding="utf-8")
    return True


def set_policy(name: str, allow: list[str], deny: list[str]) -> None:
    """覆盖写入 [hosts.<name>.policy] 段；两个列表都为空则删除该段。"""
    path = paths.hosts_file()
    if not path.exists():
        raise StoreError(f"主机 {name} 不存在")
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    # 定位已有的 policy 段并删除
    start = None
    end = None
    for idx, line in enumerate(lines):
        m = _SECTION_RE.match(line)
        if not m:
            continue
        parts = [p.strip() for p in m.group(1).split(".")]
        is_policy = (len(parts) == 3 and parts[0] == "hosts"
                     and parts[1] == name and parts[2] == "policy")
        if is_policy and start is None:
            start = idx
        elif start is not None:
            end = idx
            break
    if start is not None:
        del lines[start:(end if end is not None else len(lines))]
        text = "\n".join(lines).rstrip("\n") + "\n"

    if allow or deny:
        block = [f"[hosts.{name}.policy]"]
        if allow:
            block.append("allow = [" + ", ".join(_q(a) for a in allow) + "]")
        if deny:
            block.append("deny = [" + ", ".join(_q(d) for d in deny) + "]")
        path.write_text(
            text.rstrip("\n") + "\n\n" + "\n".join(block) + "\n", encoding="utf-8"
        )
    else:
        path.write_text(text, encoding="utf-8")


def _q(value: str) -> str:
    """TOML 单引号字面量，正则里的反斜杠无需转义。"""
    return "'" + value.replace("'", "''") + "'"


def _esc(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
