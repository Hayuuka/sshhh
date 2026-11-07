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
        "SSHHH_SETUP_TIMEOUT", "SSHHH_DATA_DIR", "SSHHH_CALLER", "SSHHH_MASTER",
        "RESULT_KEYS", "CREATE_NEW_CONSOLE", "PIP_INDEX_URL",
    }
    check("文档提到的状态名都有效", not unknown, f"未知：{sorted(unknown)}")

    for code in (10, 11, 12, 13, 14, 20):
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
    check("默认窗口超时 180 秒",
          f"{paths.DEFAULT_SETUP_TIMEOUT}" in skill_md
          and f"{paths.DEFAULT_SETUP_TIMEOUT}" in protocol_md,
          str(paths.DEFAULT_SETUP_TIMEOUT))
    check("窗口超时范围 30–600",
          f"{paths.MIN_SETUP_TIMEOUT}" in protocol_md
          and f"{paths.MAX_SETUP_TIMEOUT}" in protocol_md)
    check("并发锁 30 秒有说明", "30 秒" in protocol_md)
    check("三个超时被明确区分", "三个超时不要混" in protocol_md)

    print("\n== 运行时降级说明 ==")
    from lib import runtime  # noqa: E402

    check("pip 安装超时 150 秒", runtime.PIP_INSTALL_TIMEOUT == 150,
          str(runtime.PIP_INSTALL_TIMEOUT))
    check("pip 超时小于窗口超时（内层先超时）",
          runtime.PIP_INSTALL_TIMEOUT < paths.DEFAULT_SETUP_TIMEOUT)
    check("SKILL.md 建议首次调用 400 秒", "400 秒" in skill_md)
    check("SKILL.md 覆盖「python 命令不存在」",
          "python 命令本身不存在" in skill_md)
    check("protocol.md 记录了 pip 超时数值",
          str(runtime.PIP_INSTALL_TIMEOUT) in protocol_md)
    check("protocol.md 承认检测不到「完全没装 Python」",
          "机器完全没装 Python" in protocol_md)
    check("hint 文案是「升级」不是「首次安装」",
          "升级" in skill_md)

    print("\n" + "=" * 46)
    print(f"通过 {PASSED} 项，失败 {FAILED} 项")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
