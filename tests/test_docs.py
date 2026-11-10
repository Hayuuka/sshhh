"""文档与代码的一致性检查。

SKILL.md 是 agent 唯一的说明书，写错了 agent 就会做错事。这里把几条
容易回退的约定变成测试：

1. frontmatter 能被标准 YAML 解析，且不含注释 / HTML 注释
2. 命令表里列出的命令都真实存在
3. protocol.md 提到的状态名都真实存在
4. 文档里不出现 <SSHHH> 这类自定义占位符
5. 两个超时的数值与代码常量一致

运行：
    py -3.14 tests/test_docs.py
    或 D:/work/agentssh/.venv/Scripts/python.exe tests/test_docs.py
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from lib import paths, protocol  # noqa: E402

PASSED = 0
FAILED = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  [ok] {name}")
    else:
        FAILED += 1
        print(f"  [FAIL] {name}" + (f"  -> {detail}" if detail else ""))


def split_frontmatter(text: str) -> tuple[str, str]:
    """返回 (frontmatter 原文, 正文)。"""
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return "", text
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            return "".join(lines[1:idx]), "".join(lines[idx + 1:])
    return "", text


def parse_simple(fm: str) -> dict:
    data = {}
    for line in fm.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            data[k.strip()] = v.strip()
    return data


def main() -> int:
    skill_md = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    protocol_md = (ROOT / "references" / "protocol.md").read_text(encoding="utf-8")

    print("== frontmatter ==")
    fm, body = split_frontmatter(skill_md)
    check("存在 frontmatter", bool(fm))

    try:
        import yaml  # type: ignore

        try:
            meta = yaml.safe_load(fm) or {}
            check("YAML 解析成功", isinstance(meta, dict), str(type(meta)))
        except Exception as exc:
            meta = {}
            check("YAML 解析成功", False, str(exc))
    except ImportError:
        meta = parse_simple(fm)
        check("简易解析成功（无 PyYAML）", bool(meta))

    check("name 正确", meta.get("name") == "sshhh", str(meta.get("name")))
    check("description 足够具体",
          isinstance(meta.get("description"), str)
          and len(meta["description"]) > 40,
          str(meta.get("description"))[:40])
    check("agent_created 为 true",
          str(meta.get("agent_created")).lower() == "true",
          str(meta.get("agent_created")))

    check("frontmatter 内无 # 注释行",
          not any(line.lstrip().startswith("#") for line in fm.splitlines()),
          repr(fm))
    check("frontmatter 内无 HTML 注释", "<!--" not in fm, repr(fm))
    check("来源说明写在正文里", "<!--" in body and "agent_created" in body)

    print("\n== 命令表 ==")
    import sshhh  # noqa: E402

    documented = set(re.findall(r"^\| `([a-z]+)", skill_md, re.M))
    implemented = set(sshhh.COMMANDS)
    check("命令表非空", len(documented) >= 10, str(sorted(documented)))
    missing = documented - implemented
    check("文档里的命令都已实现", not missing, f"缺失实现：{sorted(missing)}")
    shadowed = implemented - documented - {"ls"}
    check("没有未公开的命令", not shadowed, f"未公开：{sorted(shadowed)}")

    print("\n== 状态码 ==")
    names = set(protocol.STATUS_NAMES.values())
    mentioned = set(re.findall(r"`([A-Z_]{4,})`", skill_md + protocol_md))
    unknown = mentioned - names - {
        "SSHHH_STATUS", "SSHHH_MESSAGE", "SSHHH_HINT",
        "SSHHH_SETUP_TIMEOUT", "SSHHH_SETUP_HANDOFF",
        "SSHHH_DATA_DIR", "SSHHH_MASTER",
        "RESULT_KEYS", "CREATE_NEW_CONSOLE", "CREATE_BREAKAWAY_FROM_JOB",
        "PIP_INDEX_URL",
    }
    check("文档提到的状态名都有效", not unknown, f"未知：{sorted(unknown)}")

    for code in (10, 11, 12, 13, 14, 15, 20):
        name = protocol.STATUS_NAMES[code]
        check(f"{code} = {name} 已收录", name in skill_md, name)

    print("\n== 禁止的写法 ==")
    check("没有 <SSHHH> 占位符", "<SSHHH>" not in skill_md)
    check("没有 <技能目录> 占位符", "<技能目录>" not in skill_md)
    check("脚本路径用相对写法", "scripts/sshhh.py" in skill_md)

    legacy = set(re.findall(r"\bSSHH_[A-Z]+", skill_md + protocol_md))
    check("没有 SSHH_ 前缀的旧标识", not legacy, f"发现：{sorted(legacy)}")
    legacy_lower = set(re.findall(r"~?/\.sshh\b|\.sshh/", skill_md + protocol_md))
    check("没有 .sshh 旧目录写法", not legacy_lower, f"发现：{sorted(legacy_lower)}")

    print("\n== README（中英双语）==")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme_en_path = ROOT / "README.en.md"
    check("README.en.md 存在", readme_en_path.exists())
    readme_en = readme_en_path.read_text(encoding="utf-8") if readme_en_path.exists() else ""

    check("中文 README 有「数据存在哪里」小节", "## 数据存在哪里" in readme)
    check("英文 README 有对应小节", "## Where your data lives" in readme_en)

    # 数据文件名从代码取，防止文档与实际路径漂移
    for label, text in (("中文", readme), ("英文", readme_en)):
        check(f"{label} README 写了数据目录 ~/.sshhh/", "~/.sshhh/" in text)
        check(f"{label} README 提到 {paths.vault_file().name}",
              paths.vault_file().name in text)
        check(f"{label} README 提到 {paths.hosts_file().name}",
              paths.hosts_file().name in text)
        check(f"{label} README 说明与 skill 安装位置无关",
              ("不在 skill 目录里" in text) or ("independent of where the skill" in text))

    check("中文 README 有英文版入口", "README.en.md" in readme)
    check("英文 README 有中文版入口", "README.md" in readme_en)
    check("英文 README 无 .sshh 旧目录写法",
          not re.search(r"~?/\.sshh\b", readme_en))
    check("英文 README 无 SSHH_ 旧标识",
          not re.search(r"\bSSHH_[A-Z]+", readme_en))

    print("\n== 超时数值一致 ==")
    os.environ.pop("SSHHH_SETUP_HANDOFF", None)
    handoff_default = sshhh._handoff_seconds() or 0
    check("窗口硬超时 180 秒在 protocol 里",
          f"{paths.DEFAULT_SETUP_TIMEOUT}" in protocol_md,
          str(paths.DEFAULT_SETUP_TIMEOUT))
    check("窗口超时范围 30–600",
          f"{paths.MIN_SETUP_TIMEOUT}" in protocol_md
          and f"{paths.MAX_SETUP_TIMEOUT}" in protocol_md)
    check("并发锁 30 秒有说明", "30 秒" in protocol_md)
    check("各个超时被明确区分", "超时不要混" in protocol_md)
    check("SKILL.md 说明了窗口交接", "交接" in skill_md)
    check("交接时长与代码一致",
          f"{int(handoff_default)}" in protocol_md, str(handoff_default))
    check("SKILL.md 建议首次调用 300 秒", "300 秒" in skill_md)

    print("\n== 运行时降级说明 ==")
    from lib import runtime  # noqa: E402

    check("pip 安装超时 150 秒", runtime.PIP_INSTALL_TIMEOUT == 150,
          str(runtime.PIP_INSTALL_TIMEOUT))
    check("pip 超时小于窗口超时（内层先超时）",
          runtime.PIP_INSTALL_TIMEOUT < paths.DEFAULT_SETUP_TIMEOUT)
    check("SKILL.md 建议首次调用 300 秒", "300 秒" in skill_md)
    check("SKILL.md 覆盖「python 命令不存在」",
          "python 命令本身不存在" in skill_md)
    check("protocol.md 记录了 pip 超时数值",
          str(runtime.PIP_INSTALL_TIMEOUT) in protocol_md)
    check("protocol.md 记录自举锁上限（#10）",
          str(runtime.BOOTSTRAP_LOCK_TIMEOUT) in protocol_md,
          str(runtime.BOOTSTRAP_LOCK_TIMEOUT))
    check("protocol.md 说明自举锁独立于数据锁",
          ".bootstrap" in protocol_md)
    check("SKILL.md 覆盖「另一个进程正在准备环境」",
          "正在首次准备运行环境" in skill_md)
    check("protocol.md 承认检测不到「完全没装 Python」",
          "机器完全没装 Python" in protocol_md)
    check("hint 文案是「升级」不是「首次安装」",
          "升级" in skill_md)

    print("\n== 策略与审计的覆盖范围（文档承诺 vs 实际实现）==")
    import inspect

    from lib import vault as vault_mod  # noqa: E402

    transfer_src = inspect.getsource(sshhh._transfer)
    check("put/get 执行前做策略校验", "check_transfer" in transfer_src)
    check("put/get 被拒时返回 1（与 run 一致）", "return 1" in transfer_src)
    check("put/get 写审计", "audit.write" in transfer_src)
    check("拒绝时写 transfer.denied", "transfer.denied" in transfer_src)

    audited = {
        "run": sshhh.cmd_run,
        "test": sshhh.cmd_test,
        "setpass": sshhh.cmd_setpass,
        "unlock": sshhh.cmd_unlock,
        "migrate": sshhh.cmd_migrate,
    }
    for label, fn in audited.items():
        check(f"{label} 写审计", "audit.write" in inspect.getsource(fn))

    flush_src = inspect.getsource(vault_mod.Vault._flush)
    check("vault.enc 不再写 entries 字段", 'out["entries"]' not in flush_src)
    check("旧文件里的 entries 会被清掉", 'pop("entries"' in flush_src)
    check("解密成功写 vault.open 审计",
          "vault.open" in inspect.getsource(vault_mod))

    for action in ("transfer.put", "transfer.denied", "vault.open",
                   "unlock", "migrate"):
        check(f"README 审计表列出 {action}", action in readme, action)
    check("README 说明文件通道也受策略约束",
          "allow_put" in readme and "allow_get" in readme)
    check("README 说明白名单主机的文件通道默认关闭",
          "文件通道默认关闭" in readme)
    check("protocol.md 记录了同一套策略",
          "allow_put" in protocol_md and "vault.open" in protocol_md)
    check("SKILL.md 提醒 put/get 同样受策略约束",
          "allow_put" in skill_md and "allow_get" in skill_md)

    print("\n== B 层定性：三份文档口径一致（#28）==")
    # 定位错误比实现 bug 更重要：三份文档都必须承认本地策略不是安全边界，
    # 否则 README 一句「能限制 agent 跑什么命令」就会变成安全承诺。
    for label, text in (("README.md", readme), ("SKILL.md", skill_md),
                        ("protocol.md", protocol_md)):
        check(f"{label} 写明「防手滑，非安全边界」", "防手滑" in text, "")
        check(f"{label} 承认本地策略可被绕过",
              ("可写" in text) or ("可被绕过" in text) or ("绕不过" in text), "")
    check("README 说明命令规则是 fullmatch", "fullmatch" in readme)
    check("README 说明元字符默认拒绝",
          "元字符" in readme and "默认拒绝" in readme)
    check("README 记载 allow_shell 开关", "allow_shell" in readme)
    check("protocol.md 记载 allow_shell 开关", "allow_shell" in protocol_md)
    check("SKILL.md 记载元字符默认拒绝", "元字符" in skill_md)
    check("README 旧示例已改成 fullmatch 写法",
          "'^systemctl status '" not in readme, "仍是未锚定的旧示例")

    print("\n== 审计字段口径（#29）==")
    check("protocol.md 说明 vault.open 只留前两个 argv 参数",
          "前两个" in protocol_md)
    check("README 不再宣称 caller 字段", "caller pid" not in readme)
    check("英文 README 不再宣称 caller 字段", "caller pid" not in readme_en)
    for label, text in (("README.md", readme), ("SKILL.md", skill_md),
                        ("protocol.md", protocol_md)):
        check(f"{label} 不再把 --stdin <值> 当用法",
              '--stdin "mysql' not in text and "--stdin 密" not in text, "")
    check("SKILL.md 说明 --stdin 只接受 -", "--stdin -" in skill_md)
    check("文档里没有残留 SSHHH_CALLER",
          "SSHHH_CALLER" not in (skill_md + protocol_md + readme))

    print("\n== TOFU 与指纹库（#31）==")
    check("README 说明指纹库损坏不退化成『谁都信』",
          "退化成「谁都信」" in readme, "")
    check("SKILL.md 给出『主机指纹库损坏』的处置",
          "主机指纹库损坏" in skill_md, "")
    import inspect

    from lib import transport as transport_mod  # noqa: E402

    load_src = inspect.getsource(transport_mod.load_known_hosts)
    check("加载失败路径会抛错而不是 pass",
          "TransportError" in load_src and "except Exception:\n        pass" not in load_src)
    check("指纹库写入走原子替换 + 锁",
          "atomic_write_text" in inspect.getsource(transport_mod.remember_host_keys)
          and "data_lock" in inspect.getsource(transport_mod.remember_host_keys))
    check("不再整文件 HostKeys.save 重写",
          "keys.save" not in inspect.getsource(transport_mod.Client))

    print("\n== 文件通道的本地约束（#32）==")
    from lib import store as store_mod  # noqa: E402

    settings = store_mod.Settings()
    size_label = f"{settings.transfer_max_bytes // (1024 * 1024)} MiB"
    timeout_label = f"{int(settings.transfer_timeout)} 秒"
    check(f"README 记载传输上限 {size_label}", size_label in readme, size_label)
    check(f"README 记载传输超时 {timeout_label}", timeout_label in readme)
    check("README 说明 get 不能写数据目录", "不允许写进" in readme)
    check("README 说明 put 源不能来自数据目录", "不允许来自" in readme)
    check("SKILL.md 说明 get 的落盘范围", "~/.sshhh/tmp/" in skill_md)
    check("SKILL.md 给出 --max-bytes", "--max-bytes" in skill_md)
    check("protocol.md 记录本地约束表", "文件通道的本地约束" in protocol_md)
    check("protocol.md 说明半截文件会被删",
          "半截文件" in protocol_md)

    import inspect as _inspect

    guard_src = _inspect.getsource(sshhh._guard_local_path)
    check("路径判断用 realpath 归一",
          "realpath" in _inspect.getsource(sshhh), "")
    check("get/put 都过本地路径检查", "check_transfer" in _inspect.getsource(sshhh._transfer)
          and "_guard_local_path" in _inspect.getsource(sshhh._transfer))
    check("转移实现走 Client.put_file/get_file",
          "put_file" in _inspect.getsource(sshhh._transfer)
          and "get_file" in _inspect.getsource(sshhh._transfer))
    check("上传源存在性在本地就查了", "os.path.exists" in guard_src, guard_src[:120])

    print("\n== 输出长度控制（#24）==")
    from lib import output as output_mod  # noqa: E402

    limit_label = f"{output_mod.DEFAULT_MAX_BYTES // 1024} KiB"
    check(f"README 记载默认上限 {limit_label}", limit_label in readme, limit_label)
    check("README 给出 --tail", "--tail" in readme)
    check("README 说明截断进审计", "truncated" in readme)
    check("SKILL.md 说明截断提示怎么读", "[sshhh] 输出已截断" in skill_md)
    check("SKILL.md 给出 --tail 用法", "--tail" in skill_md)
    check("protocol.md 有截断小节", "## 输出截断" in protocol_md)
    check("protocol.md 说明 tail 优先于 max-bytes",
          "优先于" in protocol_md and "--tail" in protocol_md)

    print("\n== 写入原子性与锁纪律（#9）==")
    store_src = _inspect.getsource(store_mod)
    for fn_name in ("upsert_host", "remove_host", "set_policy"):
        fn_src = _inspect.getsource(getattr(store_mod, fn_name))
        check(f"{fn_name} 自己加锁", "data_lock()" in fn_src, fn_name)
        check(f"{fn_name} 走原子替换",
              "_write_hosts" in fn_src or "atomic_write_text" in fn_src, fn_name)
    check("不再直接 write_text 落盘", "path.write_text(" not in store_src)
    check("protocol.md 说明锁下沉",
          "下沉" in protocol_md and "原子替换" in protocol_md)
    check("protocol.md 说明锁可重入", "可重入" in protocol_md)
    mig_src = _inspect.getsource(sshhh.cmd_migrate)
    check("migrate 全程持锁", "data_lock(" in mig_src, mig_src[:120])

    print("\n" + "=" * 46)
    print(f"通过 {PASSED} 项，失败 {FAILED} 项")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
