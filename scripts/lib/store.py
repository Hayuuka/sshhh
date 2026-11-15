"""主机清单（hosts.toml）。

只存连接信息，**永不存密码** —— 密码一律在 vault.enc 里按主机名索引。

写路径（#22 方案 B，2026-11-15 作者拍板）：不再做「保留注释与排版」的
文本手术 —— 读进 dict、改、用 tomli-w 整份规范重排。代价是程序写入后
不保留手写注释；换来的是「手动编辑格式稍有出入就写坏清单」这一类问题
（#2）从根上消失，加字段也不用再动手术代码。
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - 3.9/3.10 由运行时装 tomli（见 runtime.PACKAGES）
    import tomli as tomllib  # type: ignore[import-not-found,no-redef]

from . import paths
from .fsutil import atomic_write_text, read_text
from .lock import data_lock

HEADER = """\
# sshhh 主机清单 —— 由程序自动维护，也可以手写
#
# 这里没有密码字段，密码在 vault.enc 里，用 sshhh setpass <名称> 录入。
# 手动加主机后不必再做什么，第一次执行时会自动要求补充密码。
# 注意：程序写入时会整份规范重排（不保留注释与排版），字段值始终保留。

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
    # 单次 put / get 的字节上限与整体超时。默认 64 MiB / 300 秒：
    # 够传配置、日志、发布包，又不至于一次 get 把磁盘填满或挂到天荒地老（#32）。
    transfer_max_bytes: int = 64 * 1024 * 1024
    transfer_timeout: float = 300.0

    @property
    def known_hosts(self) -> Path:
        return paths.known_hosts_file()


def load() -> dict[str, Host]:
    path = paths.hosts_file()
    if not path.exists():
        return {}
    try:
        text = read_text(path)
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


def _read_doc() -> dict:
    """读整份原始 TOML 文档（不清洗、保留未知字段），供写路径使用。

    解析不了先按旧格式修一遍（#2 的遗留文件），仍然失败就抛 StoreError
    （fail-closed）：绝不基于半份清单写入，那比不写更糟。
    """
    path = paths.hosts_file()
    if not path.exists():
        return {}
    text = read_text(path)
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        try:
            return tomllib.loads(_heal_legacy(text))
        except tomllib.TOMLDecodeError as exc:
            raise StoreError(f"hosts.toml 解析失败：{exc}") from None


def _write_doc(doc: dict) -> None:
    """整份规范重排落盘：tomli-w 统一序列化 + 原子替换 + 权限收紧。

    注释与排版不保留（方案 B 的代价）；文件头的使用说明保留，清单依旧可以
    手编，程序下次写入时把手写内容重新规范排序（字段值始终保留）。
    内容里有主机名、用户名、策略，没有密码；但仍按 0600 写，省得别人顺手
    读到「这台机器上有哪些生产环境」。
    """
    try:
        import tomli_w
    except ImportError as exc:  # pragma: no cover - 运行时会装好依赖
        raise StoreError(
            "缺少 tomli-w（写 hosts.toml 需要）。请运行 sshhh manage setup "
            "重建运行环境，或 pip install tomli-w"
        ) from exc
    atomic_write_text(paths.hosts_file(), HEADER + tomli_w.dumps(doc), mode=0o600)


def upsert_host(host: Host) -> None:
    """新增或更新一台主机（保留该主机的 policy 子段与清单里的其它内容）。

    写入本身在 data_lock 内完成，调用方**不需要**自己加锁（#9）。
    """
    with data_lock():
        doc = _read_doc()
        hosts = doc.setdefault("hosts", {})
        item = hosts.setdefault(host.name, {})
        item["host"] = host.host
        item["user"] = host.user
        item["port"] = host.port
        if host.description:
            item["description"] = host.description
        else:
            item.pop("description", None)
        if host.sudo:
            item["sudo"] = True
        else:
            item.pop("sudo", None)
        if host.allow_shell:
            item["allow_shell"] = True
        else:
            item.pop("allow_shell", None)
        if host.key_file:
            item["key_file"] = host.key_file
        else:
            item.pop("key_file", None)
        # policy 子段原样保留（set_policy 专门负责它）
        _write_doc(doc)


def remove_host(name: str) -> bool:
    with data_lock():
        if not paths.hosts_file().exists():
            return False
        doc = _read_doc()
        hosts = doc.get("hosts") or {}
        if name not in hosts:
            return False
        del hosts[name]
        _write_doc(doc)
        return True


def set_policy(name: str, allow: list[str], deny: list[str], *,
               allow_put: list[str] | None = None,
               allow_get: list[str] | None = None,
               deny_put: list[str] | None = None,
               deny_get: list[str] | None = None) -> None:
    """覆盖写入 [hosts.<name>.policy] 段；全部为空则删除该段。

    文件通道的四条规则是关键字参数，老调用方（只传 allow / deny）不受影响。
    """
    with data_lock():
        if not paths.hosts_file().exists():
            raise StoreError(f"主机 {name} 不存在")
        doc = _read_doc()
        hosts = doc.get("hosts") or {}
        if name not in hosts:
            raise StoreError(f"主机 {name} 不存在")
        rules = {
            "allow": allow, "deny": deny,
            "allow_put": allow_put or [], "allow_get": allow_get or [],
            "deny_put": deny_put or [], "deny_get": deny_get or [],
        }
        pol = {k: v for k, v in rules.items() if v}
        if pol:
            hosts[name]["policy"] = pol
        else:
            hosts[name].pop("policy", None)
        _write_doc(doc)
