"""主机清单（hosts.toml）。

只存连接信息，**永不存密码** —— 密码一律在 vault.enc 里按主机名索引。
"""

from __future__ import annotations

import json
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

# TOML 裸键只允许 A-Za-z0-9_-；中文、空格、点号等一律要用带引号的键
_BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_HEADER_RE = re.compile(r"^(\s*)\[([^\[\]]+)\](\s*)$")


def _key(name: str) -> str:
    """把主机名写成 TOML 键：合法的用裸键，其余套双引号。

    json 的双引号转义规则（\\" \\\\ \\n \\uXXXX）恰好是 TOML 基本字符串
    的子集，所以直接复用它，省得自己处理控制字符。
    """
    return name if _BARE_KEY_RE.match(name) else json.dumps(name, ensure_ascii=False)


def _section_path(line: str) -> list[str] | None:
    """解析 `[hosts."名字".policy]` 这类段头的键路径。

    交给 tomllib 解析，引号、转义、点号都由它兜住；不是合法段头则返回 None。
    """
    stripped = line.strip()
    if not stripped.startswith("[") or stripped.startswith("[["):
        return None
    try:
        node = tomllib.loads(stripped)
    except tomllib.TOMLDecodeError:
        return None
    path: list[str] = []
    while isinstance(node, dict) and len(node) == 1:
        key = next(iter(node))
        path.append(key)
        node = node[key]
    if not isinstance(node, dict) or node:
        return None
    return path or None


def _heal_legacy(text: str) -> str:
    """把历史上写坏的裸键段头补上引号：`[hosts.李家豪LJH]` → `[hosts."李家豪LJH"]`。

    只改动整行解析不了的段头，正常文件原样返回，可安全地反复调用。
    """
    lines = text.splitlines()
    changed = False
    for idx, line in enumerate(lines):
        if _section_path(line) is not None:
            continue
        m = _HEADER_RE.match(line)
        if not m:
            continue
        parts = [_key(p.strip()) for p in m.group(2).split(".")]
        fixed = f"{m.group(1)}[{'.'.join(parts)}]"
        if _section_path(fixed) is None:
            continue
        lines[idx] = fixed
        changed = True
    if not changed:
        return text
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


class StoreError(Exception):
    pass


# 命令里出现这些字符就默认拒绝。它们让「一条命令」变成「一串命令」，
# 任何按整条字符串写的 allow / deny 规则都会被绕开（#28）。
_SHELL_META = frozenset(";&|$`\n\r<>")

_META_LABEL = {
    "\n": "\\n", "\r": "\\r",
}


def _matches(pattern: str, text: str) -> bool:
    """整条字符串匹配一条规则。

    用 fullmatch 而不是 search：`allow = ['df -h']` 在 search 下会放过
    `x; rm -rf /; df -h`。规则写坏（非法正则）时退化成字面全串比较，
    不让一条笔误把整台机器变成「不设防」或「完全不可用」。
    """
    try:
        return re.fullmatch(pattern, text) is not None
    except re.error:
        return pattern == text


@dataclass
class Policy:
    """主机策略。

    `allow` / `deny` 管 `run` 的命令；`allow_put` / `deny_put` 等管文件
    通道，匹配的是**远端路径**（put 看目标、get 看源）。命令策略和文件策略
    分开配置，是因为它们拦的是完全不同的东西：一条白名单管不住
    `get /etc/shadow`。

    定性（重要）：这是**防手滑，非安全边界**。hosts.toml 和本文件对同用户
    的进程都可写，agent 想绕开随时能绕开（改文件、直接调 lib）。真正的强制
    只能在服务端做。这里的价值是让「顺手犯的错」付出一点摩擦成本，并留下
    拒绝记录，而不是拦住有意绕过的调用方。
    """

    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    allow_put: list[str] = field(default_factory=list)
    allow_get: list[str] = field(default_factory=list)
    deny_put: list[str] = field(default_factory=list)
    deny_get: list[str] = field(default_factory=list)

    def check(self, command: str, *, allow_shell: bool = False) -> str | None:
        """校验一条 `run` 命令。返回 None 表示放行，否则返回拒绝原因。

        `allow_shell=True` 的主机跳过元字符检查（例如需要 `2>/dev/null`
        或 `a && b` 的场景），代价是 allow / deny 只对整条命令原样生效。
        """
        if not allow_shell:
            meta = sorted({_META_LABEL.get(ch, ch) for ch in command
                           if ch in _SHELL_META})
            if meta:
                return ("命令包含 shell 元字符（" + "、".join(meta)
                        + "），默认拒绝；确需使用请在主机配置里加 "
                          "allow_shell = true")
        for pat in self.deny:
            if _matches(pat, command):
                return f"命中禁止规则 /{pat}/"
        if self.allow:
            for pat in self.allow:
                if _matches(pat, command):
                    return None
            return "未命中任何允许规则（该主机处于白名单模式）"
        return None

    def check_transfer(self, direction: str, remote_path: str) -> str | None:
        """校验 put / get 的远端路径。返回 None 表示放行。

        默认关闭：主机一旦配了命令白名单（`allow`），文件通道就必须
        显式用 `allow_put` / `allow_get` 打开。否则「只允许 df -h 的机器」
        仍然可以 `get /etc/shadow` —— 白名单等于没配。
        """
        is_put = direction == "put"
        allow = self.allow_put if is_put else self.allow_get
        deny = self.deny_put if is_put else self.deny_get
        label = "上传" if is_put else "下载"

        for pat in deny:
            if re.search(pat, remote_path):
                return f"{label}命中禁止规则 /{pat}/"
        if allow:
            for pat in allow:
                if re.search(pat, remote_path):
                    return None
            return f"远端路径未命中任何允许规则（{label}处于白名单模式）"
        if self.allow:
            key = "allow_put" if is_put else "allow_get"
            return f"该主机启用了命令白名单，{label}默认关闭（需配置 {key}）"
        return None

    @property
    def active(self) -> bool:
        return bool(
            self.allow or self.deny
            or self.allow_put or self.allow_get
            or self.deny_put or self.deny_get
        )


@dataclass
class Host:
    name: str
    host: str
    user: str
    port: int = 22
    description: str = ""
    sudo: bool = False
    key_file: str | None = None
    # 允许命令里出现 shell 元字符（`;` `&&` `|` 重定向等）。默认关闭，
    # 见 Policy.check：#28 之后含元字符的命令默认拒绝。
    allow_shell: bool = False
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
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise StoreError(f"hosts.toml 读取失败：{exc}") from None
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        # 旧版本把中文别名写成了裸键，整份清单会解析不了。
        # 先按老格式修一遍再试，这样升级后不必手工改文件。
        try:
            raw = tomllib.loads(_heal_legacy(text))
        except tomllib.TOMLDecodeError:
            raise StoreError(f"hosts.toml 解析失败：{exc}") from None

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
            allow_shell=bool(item.get("allow_shell", False)),
            policy=Policy(
                allow=[str(x) for x in (pol.get("allow") or [])],
                deny=[str(x) for x in (pol.get("deny") or [])],
                allow_put=[str(x) for x in (pol.get("allow_put") or [])],
                allow_get=[str(x) for x in (pol.get("allow_get") or [])],
                deny_put=[str(x) for x in (pol.get("deny_put") or [])],
                deny_get=[str(x) for x in (pol.get("deny_get") or [])],
            ),
        )
    return hosts


def get(name: str) -> Host | None:
    return load().get(name)


def _section_index(text: str, name: str) -> tuple[int, int] | None:
    """返回 [hosts.<name>] 段的 (起始行, 结束行)。"""
    lines = text.splitlines()
    start = None
    for idx, line in enumerate(lines):
        path = _section_path(line)
        if path is None:
            continue
        if len(path) >= 2 and path[0] == "hosts" and path[1] == name:
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
    text = _heal_legacy(path.read_text(encoding="utf-8")) if path.exists() else HEADER

    block = [f"[hosts.{_key(host.name)}]"]
    if host.description:
        block.append(f'description = "{_esc(host.description)}"')
    block.append(f'host = "{_esc(host.host)}"')
    block.append(f"port = {host.port}")
    block.append(f'user = "{_esc(host.user)}"')
    if host.sudo:
        block.append("sudo = true")
    if host.allow_shell:
        block.append("allow_shell = true")
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
            if _section_path(lines[section_end]) is not None:
                break
            section_end += 1
        new_lines = lines[:start] + block + [""] + lines[section_end:]
        text = "\n".join(new_lines).rstrip("\n") + "\n"

    path.write_text(text, encoding="utf-8")


def remove_host(name: str) -> bool:
    path = paths.hosts_file()
    if not path.exists():
        return False
    text = _heal_legacy(path.read_text(encoding="utf-8"))
    span = _section_index(text, name)
    if span is None:
        return False
    start, end = span
    lines = text.splitlines()
    del lines[start:end]
    path.write_text("\n".join(lines).rstrip("\n") + "\n", encoding="utf-8")
    return True


def set_policy(name: str, allow: list[str], deny: list[str], *,
               allow_put: list[str] | None = None,
               allow_get: list[str] | None = None,
               deny_put: list[str] | None = None,
               deny_get: list[str] | None = None) -> None:
    """覆盖写入 [hosts.<name>.policy] 段；全部为空则删除该段。

    文件通道的四条规则是关键字参数，老调用方（只传 allow / deny）不受影响。
    """
    path = paths.hosts_file()
    if not path.exists():
        raise StoreError(f"主机 {name} 不存在")
    text = _heal_legacy(path.read_text(encoding="utf-8"))
    lines = text.splitlines()

    # 定位已有的 policy 段并删除
    start = None
    end = None
    for idx, line in enumerate(lines):
        path_ = _section_path(line)
        if path_ is None:
            continue
        is_policy = (path_ == ["hosts", name, "policy"])
        if is_policy and start is None:
            start = idx
        elif start is not None:
            end = idx
            break
    if start is not None:
        del lines[start:(end if end is not None else len(lines))]
        text = "\n".join(lines).rstrip("\n") + "\n"

    rules = [
        ("allow", allow),
        ("deny", deny),
        ("allow_put", allow_put or []),
        ("allow_get", allow_get or []),
        ("deny_put", deny_put or []),
        ("deny_get", deny_get or []),
    ]
    block = [f"[hosts.{_key(name)}.policy]"]
    for key, values in rules:
        if values:
            block.append(f"{key} = [" + ", ".join(_q(v) for v in values) + "]")

    if len(block) > 1:
        path.write_text(
            text.rstrip("\n") + "\n\n" + "\n".join(block) + "\n", encoding="utf-8"
        )
    else:
        path.write_text(text, encoding="utf-8")


def _q(value: str) -> str:
    """TOML 单引号字面量，正则里的反斜杠无需转义。

    字面量字符串里没有任何办法表示单引号（写两个是无效语法，会让整份清单解析失败），
    这种情况退回双引号基本字符串。
    """
    if "'" in value:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return "'" + value + "'"


def _esc(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
