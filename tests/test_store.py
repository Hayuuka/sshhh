"""主机清单（hosts.toml）读写测试。

重点覆盖「别名不是合法 TOML 裸键」这一类问题：中文、点号、空格、引号都不该
让整份清单写坏——写坏一次就等于所有主机一起不可用。

运行：
    D:/work/agentssh/.venv/Scripts/python.exe tests/test_store.py
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import tomllib
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

_TMP = Path(tempfile.mkdtemp(prefix="sshhh-store-"))
os.environ["SSHHH_DATA_DIR"] = str(_TMP)

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
    f = paths.hosts_file()
    if f.exists():
        f.unlink()


def raw() -> str:
    return paths.hosts_file().read_text(encoding="utf-8")


# 都是不能直接当 TOML 裸键的名字
NAMES = [
    "李家豪LJH",      # 中文开头（issue 里的原始案例）
    "prod.cn",        # 点号：裸键会被解析成嵌套表
    "my host",        # 空格
    'say "hi"',       # 双引号
    "反斜杠\\测试",     # 反斜杠（引号内必须转义）
    "ハード-1",        # 日文
]


def main() -> int:
    print("== 非 ASCII / 特殊字符别名 ==")
    reset()
    for i, name in enumerate(NAMES):
        store.upsert_host(store.Host(name=name, host=f"10.0.0.{i}", user="root"))
        loaded = store.load()
        check(f"写入后立刻可读：{name}", name in loaded, str(list(loaded)))
        check(f"字段无损：{name}",
              loaded.get(name) is not None
              and loaded[name].host == f"10.0.0.{i}"
              and loaded[name].user == "root")
    check("清单整体是合法 TOML", bool(tomllib.loads(raw())))
    check("一台主机都没丢", len(store.load()) == len(NAMES),
          f"{sorted(store.load())}")

    print("\n== 重复写入是覆盖不是追加 ==")
    store.upsert_host(store.Host(name="李家豪LJH", host="10.9.9.9", user="ubuntu"))
    hosts = store.load()
    check("同名只留一台", len(hosts) == len(NAMES), str(sorted(hosts)))
    check("内容已更新", hosts["李家豪LJH"].host == "10.9.9.9"
          and hosts["李家豪LJH"].user == "ubuntu")
    occurrences = raw().count("李家豪LJH")
    check("文件里只出现一次段头", occurrences == 1, raw())

    print("\n== 策略子段 ==")
    store.set_policy("prod.cn", ["^ls"], ["^rm"])
    h = store.get("prod.cn")
    check("策略写进去了", h is not None and h.policy.allow == ["^ls"]
          and h.policy.deny == ["^rm"], str(raw()))
    store.set_policy("prod.cn", ["^ls", "^cat"], ["^rm -rf", "^shutdown"])
    h = store.get("prod.cn")
    check("再写一次不重复", h is not None
          and sorted(h.policy.allow) == ["^cat", "^ls"]
          and sorted(h.policy.deny) == ["^rm -rf", "^shutdown"], raw())
    check("其它主机的策略不受影响", store.get("李家豪LJH").policy.active is False)
    store.set_policy("prod.cn", [], [])
    check("清空后段被删掉", store.get("prod.cn").policy.active is False
          and "[hosts.\"prod.cn\".policy]" not in raw())

    print("\n== 含单引号的规则不会写坏清单 ==")
    store.set_policy("my host", [], ["^it's"])
    h = store.get("my host")
    check("清单仍可解析", h is not None)
    check("规则原样保留", h.policy.deny == ["^it's"], str(raw()))

    print("\n== 删除 ==")
    check("删除成功", store.remove_host("my host") is True)
    check("真的没了", "my host" not in store.load())
    check("删除后清单仍合法", bool(tomllib.loads(raw())))
    check("删不存在的返回 False", store.remove_host("不存在的主机") is False)

    print("\n== 旧版本写坏的清单自动修复 ==")
    reset()
    paths.hosts_file().write_text(
        "# 手写清单\n"
        "\n"
        "[hosts.李家豪LJH]\n"
        'host = "1.2.3.4"\n'
        "port = 22\n"
        'user = "root"\n'
        "\n"
        "[hosts.李家豪LJH.policy]\n"
        "deny = ['^rm']\n"
        "\n"
        "[hosts.legacy]\n"
        'host = "5.6.7.8"\n'
        'user = "root"\n',
        encoding="utf-8",
    )
    h = store.load().get("李家豪LJH")
    check("坏文件也能读出来", h is not None and h.host == "1.2.3.4", raw())
    check("子段策略也读到了", h is not None and h.policy.deny == ["^rm"])
    check("好的段不受影响", "legacy" in store.load())
    check("读操作不擅自改文件", "[hosts.李家豪LJH]" in raw(), raw())

    store.set_policy("李家豪LJH", [], ["^rm -rf"])
    check("写入时顺手修复文件", "[hosts.李家豪LJH]" not in raw(), raw())
    check("修复后清单合法", bool(tomllib.loads(raw())))
    check("修复后中文别名仍能对上", "李家豪LJH" in store.load())
    check("修复后原有主机没丢", "legacy" in store.load())

    print("\n== 裸键名字走老格式（不必加引号）==")
    reset()
    store.upsert_host(store.Host(name="hk-prod_1", host="8.8.8.8", user="root"))
    check("普通名字不加引号", "[hosts.hk-prod_1]" in raw(), raw())

    shutil.rmtree(_TMP, ignore_errors=True)
    print("\n" + "=" * 46)
    print(f"通过 {PASSED} 项，失败 {FAILED} 项")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
