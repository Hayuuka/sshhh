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

from . import integrity, paths
from .fsutil import atomic_write_text, read_text
from .lock import data_lock

HEADER = """\
# sshhh 主机清单 —— 由程序自动维护，也可以手写
#
# 这里没有密码字段，密码在 vault.enc 里，用 sshhh setpass <名称> 录入。
# 手动加主机后不必再做什么，第一次执行时会自动要求补充密码。
# 注意：程序写入时会整份规范重排（不保留注释与排版），字段值始终保留。
# 注意：清单带完整性签名（[sshhh_integrity] 段）—— 手编之后连接会被拒绝，
# 这是预期行为：检查内容无误后执行 sshhh manage reseal 重新签名。

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


# 完整性签名失效时的指引（#18）。这段话写给最终用户：签名失效最常见的
# 原因是本人手编了 hosts.toml（预期行为，reseal 一次即可）；但也可能是
# 别的进程改了清单 —— 所以必须先检查内容，再重新签名。
_RESEAL_HINT = (
    "如果你刚手动编辑过 hosts.toml，这是预期行为：先检查文件内容是否符合"
    "你的本意，然后在你的终端执行 sshhh manage reseal 重新签名。\n"
    "如果你没有改过它，说明有别的程序动过这份清单——先弄清楚改了什么。"
)


def _verify_integrity(doc: dict) -> None:
    """读路径的强制验签点。签名密钥未绑定（密码库没解锁）时跳过。

    run / test / put / get / harden 以及 setpass / keygen / keyimport /
    keyshow 全部先解锁密码库才走到这里（#39 的调用顺序纪律），所以这些
    路径必然验签；list / status / policy 在锁定状态下仍可用来检查被改动
    的文件。
    """
    key = integrity.mac_key()
    if key is None:
        return
    problem = integrity.verify_doc(doc, key)
    if problem is not None:
        raise StoreError(f"{problem}\n{_RESEAL_HINT}")


# 命令里出现这些字符就默认拒绝。它们让「一条命令」变成「一串命令」，
# 任何按整条字符串写的 allow / deny 规则都会被绕开（#28）。
_SHELL_META = frozenset(";&|$`\n\r<>")

_META_LABEL = {
    "\n": "\\n", "\r": "\\r",
}


def _matches(pattern: str, text: str) -> bool:
    """整条字符串匹配一条命令规则。

    用 fullmatch 而不是 search：`allow = ['df -h']` 在 search 下会放过
    `x; rm -rf /; df -h`。规则写坏（非法正则）时退化成字面全串比较，
    不让一条笔误把整台机器变成「不设防」或「完全不可用」。
    """
    try:
        return re.fullmatch(pattern, text) is not None
    except re.error:
        return pattern == text


def _matches_path(pattern: str, text: str) -> bool:
    """子串匹配一条文件规则（re.search 语义：命中即算）。

    非法正则退化成字面子串比较 —— 与命令规则的降级语义一致（#43）。
    旧实现直接裸调 re.search，一条写错的规则（手写少个右括号很常见）
    会让 put/get 以「内部错误」崩掉，同一份配置里其它合法规则全部失效。
    """
    try:
        return re.search(pattern, text) is not None
    except re.error:
        return pattern in text


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

        文件规则是 re.search 的子串命中语义（命令规则是 fullmatch，两者
        拦的东西不同不必同构）：`allow_get = ['^/var/log/']` 是常规写法，
        不带 `^` 锚定会把 `/var/tmp/evil` 也放进来。规则写坏时退化成
        字面子串比较，不让一条笔误把 put/get 弄崩（#43）。
        """
        is_put = direction == "put"
        allow = self.allow_put if is_put else self.allow_get
        deny = self.deny_put if is_put else self.deny_get
        label = "上传" if is_put else "下载"

        for pat in deny:
            if _matches_path(pat, remote_path):
                return f"{label}命中禁止规则 /{pat}/"
        if allow:
            for pat in allow:
                if _matches_path(pat, remote_path):
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
    """读主机清单。密码库已解锁时会先验完整性签名，失败抛 StoreError
    （fail-closed，#18）：宁可拒绝服务，也不按一份被改过的清单放行命令。

    验签与解析共用**同一次读取**的文档（#46）：旧实现验签读一次、解析
    再读一次，两次之间文件被并发替换的话，验签对象和实际使用的文档可能
    不是同一份 —— fail-closed 在窗口期被架空。
    """
    path = paths.hosts_file()
    if not path.exists():
        return {}
    doc = _read_doc()
    _verify_integrity(doc)
    return _hosts_from_doc(doc)


def _hosts_from_doc(raw: dict) -> dict[str, Host]:
    """从解析好的 TOML 文档构建 Host 对象。load 与 load_unverified 共用。"""
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


def load_unverified() -> dict[str, Host]:
    """不做完整性验签的读取，仅供 list / status / policy 这类只读展示。

    这些视图的存在意义之一就是让用户在被改动的清单上「看看改了什么」，
    所以不能被验签挡住。任何会触发连接或策略判定的路径禁止用本函数。
    """
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

    return _hosts_from_doc(raw)


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
    try:
        text = read_text(path)
    except OSError as exc:
        raise StoreError(f"hosts.toml 读取失败：{exc}") from None
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        try:
            return tomllib.loads(_heal_legacy(text))
        except tomllib.TOMLDecodeError as exc:
            raise StoreError(f"hosts.toml 解析失败：{exc}") from None


def _write_doc(doc: dict, *, force_seal: bool = False) -> None:
    """整份规范重排落盘：tomli-w 统一序列化 + 完整性签名 + 原子替换。

    签名续签规则（#18，防洗白）：
    - 文件尚不存在 → 直接签名（首台主机的正常路径）
    - 原有文件带**有效**签名 → 重签（向导加主机、迁移都会自动续签）
    - 原有文件没有签名或签名已失效 → **不签名**照写：一次普通写入不能把
      被篡改或遗留未签的清单洗成「已验证」状态；强制路径依旧 fail-closed，
      直到用户检查内容后显式 reseal。
    `force_seal` 仅供 manage reseal（用户本人检查过内容后的显式确认）。
    """
    try:
        import tomli_w
    except ImportError as exc:  # pragma: no cover - 运行时会装好依赖
        raise StoreError(
            "缺少 tomli-w（写 hosts.toml 需要）。请运行 sshhh manage setup "
            "重建运行环境，或 pip install tomli-w"
        ) from exc
    path = paths.hosts_file()
    key = integrity.mac_key()
    if force_seal:
        if key is None:
            raise StoreError("密码库未解锁，无法生成 hosts.toml 的完整性签名")
        doc = integrity.seal_doc(doc, key)
    elif not path.exists():
        # 全新清单：没有历史可洗白，直接进入签名状态
        if key is not None:
            doc = integrity.seal_doc(doc, key)
    else:
        old = _read_doc()
        if integrity.SECTION in old:
            # 已带签名段的文件：必须持钥重签。所有合法写路径（向导 / 迁移 /
            # reseal）都先解锁了密码库；没持钥就写，唯一结局是把签名弄成
            # 陈旧值让下一次连接 fail-closed —— 不如现在就拒绝，把话说清楚。
            if key is None:
                raise StoreError(
                    "hosts.toml 带完整性签名，写入需要解锁密码库来重新签名；"
                    "请使用 sshhh 的管理命令操作，而不是直接调内部写函数"
                )
            if integrity.verify_doc(old, key) is None:
                doc = integrity.seal_doc(doc, key)
            # 原有签名已失效 → 不签名照写：普通写入不能把被篡改或遗留
            # 未签的清单洗成「已验证」状态，强制路径依旧 fail-closed，
            # 直到用户检查内容后显式 reseal。
        elif key is not None and not old.get("hosts"):
            # 空清单的首次写入（升级前的遗留空文件）：没有可保护的内容，
            # 直接进入签名状态
            doc = integrity.seal_doc(doc, key)
    atomic_write_text(path, HEADER + tomli_w.dumps(doc), mode=0o600)


def reseal() -> None:
    """给当前 hosts.toml 重新签名（manage reseal，用户本人执行）。

    前提：密码库已解锁 —— 签名密钥从主密码派生。文件解析失败抛 StoreError，
    绝不基于半份清单签名。签名覆盖当前文件的全部内容，所以必须在用户
    检查过内容之后调用。
    """
    with data_lock():
        doc = _read_doc()
        _write_doc(doc, force_seal=True)


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
