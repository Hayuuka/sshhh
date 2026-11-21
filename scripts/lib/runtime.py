"""运行时自举。

问题：agent 调用的 `python` 往往是宿主的嵌入式解释器（没有 paramiko，
也没有 tkinter）。直接在它上面跑会立刻崩。

做法：第一次运行时在 `~/.sshhh/venv` 建一个独立虚拟环境并装好依赖，
之后所有调用都切到那个解释器。全机器共享一份，装多少份 skill 都不重复。
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from . import paths

REQUIRED_MODULES = ("paramiko", "cryptography", "keyring", "tomli_w")
# 版本兼容区间（#48 / TM-C5）：自举装的依赖必须可复现 —— 下限是验证过
# 行为的最低线，上限挡住未测试的大版本，上游发版不再直接进用户 venv。
# 升级 = 改这里 + 跑全部测试（CI 安装的是同一组约束）。
# 2026-11 验证矩阵：paramiko 5.1 / cryptography 50.0 / keyring 25.7 /
# tomli-w 1.2 / tomli 2.5。cryptography 50.x 不再解析 OpenSSH 容器的
# 行为差异已在 sshkeys.normalize_pem 里对齐（新旧两代都兼容）。
PACKAGES = (
    "paramiko>=4,<6",
    "cryptography>=44,<51",
    "keyring>=24,<26",
    "tomli-w>=1.0,<2",
    # 3.9/3.10 没有标准库 tomllib，读 hosts.toml 需要 tomli（#22）
    'tomli>=2,<3; python_version < "3.11"',
)

_BOOT_FLAG = "SSHHH_BOOTSTRAPPED"
_ENTRY = Path(__file__).resolve().parent.parent / "sshhh.py"

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# 安装超时。必须显著小于 agent 常见的命令超时（200-400 秒），
# 否则 pip 卡在网络上时，agent 会先被自己的超时打断，看不到这里的失败提示。
# 实测有缓存时约 35 秒，慢网络 100 秒左右；150 秒足够覆盖绝大多数情况。
PIP_UPGRADE_TIMEOUT = 60
PIP_INSTALL_TIMEOUT = 150

# 自举锁的等待上限。要覆盖「建 venv 180s + 升级 pip 60s + 装依赖 150s」的
# 最坏情况，但不能无限等：等不到就返回 NO_RUNTIME 让调用方稍后重试，比挂到
# agent 自己的命令超时为止要好。
BOOTSTRAP_LOCK_TIMEOUT = 300


class RuntimeError_(Exception):
    """运行环境无法就绪。消息应当是人类可读、可转告用户的。"""


class PythonTooOldError(RuntimeError_):
    """找到的 Python 版本低于 3.9。

    可达范围说明（重要）：
    脚本本身必须由某个 Python 启动，所以「机器上完全没装 Python」这种情况
    根本走不到这里 —— shell 会先报 command not found，脚本压根不会运行。
    真正能触发本异常的只有「有 Python 但太旧」：find_base_python() 的所有
    候选（含 sys.executable）都低于 3.9。

    因此给用户的指引只能是「升级 Python」，不能是「安装 Python」——
    后者要由 agent 在命令根本跑不起来时自行判断。
    """


def _interpreter_version(executable: str | Path) -> tuple[int, int] | None:
    """探测目标解释器的 (major, minor)。探测失败返回 None。"""
    try:
        proc = subprocess.run(
            [str(executable), "-c",
             "import sys;print(sys.version_info.major, sys.version_info.minor)"],
            capture_output=True, timeout=20, text=True,
            creationflags=_NO_WINDOW,
        )
        if proc.returncode != 0:
            return None
        parts = proc.stdout.strip().split()
        # 打印成两个整数再解析，不用 eval —— 输出虽受控，但没理由留着 eval（#21）
        if len(parts) != 2:
            return None
        return int(parts[0]), int(parts[1])
    except Exception:
        return None


def deps_ok(executable: str | Path) -> bool:
    """检查 executable 里关键依赖是否齐全。

    tomli 要不要在检查清单里，取决于**被检查的那个解释器**的版本而不是
    当前进程（#42）：宿主 Python 3.9 拉起自举、选中 3.14 建 venv 时，
    按当前进程版本补查 tomli 会让一个依赖齐全的 venv 永远判为不可用，
    这台机器上就再也自举不起来了。
    """
    version = _interpreter_version(executable)
    if version is None:
        return False
    try:
        modules = list(REQUIRED_MODULES)
        if version < (3, 11):
            modules.append("tomli")
        code = "import " + ",".join(modules)
        proc = subprocess.run(
            [str(executable), "-c", code],
            capture_output=True,
            timeout=30,
            creationflags=_NO_WINDOW,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _python_version_ok(executable: str) -> bool:
    version = _interpreter_version(executable)
    return version is not None and version >= (3, 9)


def find_base_python() -> str | None:
    """找一个可用的基础解释器来建 venv。"""
    candidates: list[list[str]] = []
    if os.name == "nt":
        # 按版本号从新到旧逐个探测（#21）：写死 py -3.14 在 3.15 发布后
        # 会一直错过更新的解释器。不存在的版本 py 启动器立刻失败，探测成本可忽略。
        for minor in range(15, 8, -1):
            candidates.append(["py", f"-3.{minor}"])
        candidates.append(["py", "-3"])
        candidates.append(["py"])
    candidates.append(["python3"])
    candidates.append(["python"])
    candidates.append([sys.executable])

    for cmd in candidates:
        try:
            proc = subprocess.run(
                [*cmd, "-c", "import sys;print(sys.executable)"],
                capture_output=True, timeout=20, text=True,
                creationflags=_NO_WINDOW,
            )
            if proc.returncode != 0:
                continue
            exe = proc.stdout.strip()
            if exe and Path(exe).exists() and _python_version_ok(exe):
                return exe
        except Exception:
            continue
    return None


def _create_venv(base_python: str) -> bool:
    venv = paths.venv_dir()
    if venv.exists():
        # 上次建到一半，清掉重来
        import shutil

        shutil.rmtree(venv, ignore_errors=True)
    try:
        proc = subprocess.run(
            [base_python, "-m", "venv", str(venv)],
            capture_output=True, timeout=180, creationflags=_NO_WINDOW,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _install(venv_py: Path) -> str | None:
    """安装依赖。成功返回 None，失败返回可转告用户的中文原因。"""
    try:
        subprocess.run(
            [str(venv_py), "-m", "pip", "install", "--quiet", "--upgrade", "pip"],
            capture_output=True, timeout=PIP_UPGRADE_TIMEOUT,
            creationflags=_NO_WINDOW,
        )
        proc = subprocess.run(
            [str(venv_py), "-m", "pip", "install", "--quiet", *PACKAGES],
            capture_output=True, timeout=PIP_INSTALL_TIMEOUT,
            creationflags=_NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        return (
            f"安装依赖超时（超过 {PIP_INSTALL_TIMEOUT} 秒），网络可能不通"
        )
    except Exception as exc:
        return f"安装依赖失败：{exc}"

    if proc.returncode == 0 and deps_ok(venv_py):
        return None

    tail = _tail(proc.stderr) or _tail(proc.stdout)
    if proc.returncode == 0:
        # 装是装上了，但自检不过（#42）：这不是 pip 的错，措辞必须分开，
        # 否则按「安装失败」排查网络会南辕北辙
        reason = "依赖已安装，但安装后的自检未通过（导入关键模块失败）"
        if tail:
            reason += f"：{tail}"
        return reason
    reason = f"pip 安装失败（退出码 {proc.returncode}）"
    if tail:
        reason += f"：{tail}"
    return reason


def _tail(data: bytes | None, lines: int = 3, limit: int = 240) -> str:
    """取输出的最后几行，去掉空行，用于错误提示。"""
    if not data:
        return ""
    text = data.decode("utf-8", "replace")
    parts = [ln.strip() for ln in text.splitlines() if ln.strip()]
    joined = " | ".join(parts[-lines:])
    return joined[:limit]


def _reexec(executable: Path) -> None:
    """用目标解释器重新执行本脚本。

    两个平台必须分开处理，因为 os.execv 的语义完全不同：

    POSIX：原语级「原地换身」，进程号不变、文件描述符不变、父进程不变，
    调用方一直在等这个进程，输出顺序天然正确。保持 os.execv。

    Windows：CPython 是模拟实现 —— spawn 一个子进程后父进程立即退出，
    且不等待。宿主看到命令结束时子进程还没写出 stdout，于是
      * 输出丢失（宿主已读完捕获，子进程才写）
      * 输出错位一轮（写进了下一次调用的捕获）
    这两种都是 exit 0 + 空输出，agent 无从判断，比报错更危险。
    所以 Windows 改为前台等待子进程，再透传退出码。

    另外 Windows 的 os.execv 不做参数引号处理（`"df -h"` 会被拆成两个），
    这里传 list 给 subprocess，由 list2cmdline 负责引用，顺带修掉。
    """
    argv = [str(executable), str(_ENTRY), *sys.argv[1:]]

    if os.name != "nt":
        os.environ[_BOOT_FLAG] = "1"
        os.execv(str(executable), argv)
        return

    env = dict(os.environ)
    env[_BOOT_FLAG] = "1"
    try:
        proc = subprocess.run(argv, env=env)
    except KeyboardInterrupt:
        # 子进程同在一个控制台，也会收到 Ctrl+C，等它自己收尾即可
        sys.exit(130)
    sys.exit(proc.returncode)


def ensure(argv: list[str] | None = None) -> None:
    """确保当前进程运行在依赖齐全的解释器上，必要时切换或安装。

    成功则直接返回（可能已经 exec 到新解释器，永不返回）。
    失败抛 RuntimeError_。
    """
    if os.environ.get(_BOOT_FLAG) == "1":
        return

    venv_py = paths.venv_python()

    # 已经在自己的 venv 里
    try:
        if Path(sys.executable).resolve() == venv_py.resolve():
            if deps_ok(sys.executable):
                return
    except Exception:
        pass

    # 当前解释器本身就能用（比如用户手动用装好依赖的 python 调）
    if deps_ok(sys.executable):
        return

    # 有现成的 venv，切过去
    if venv_py.exists() and deps_ok(venv_py):
        _reexec(venv_py)

    # 需要新建。多 agent 同时首跑是核心场景（README 就是冲着这个写的），
    # 所以整个「检查 → 建 venv → 装依赖」必须串行：_create_venv 开头会 rmtree，
    # 后到的进程会把前一个正在 pip install 的目录删掉，最后留下一个怎么都装不好
    # 的坏环境（#10）。
    from .lock import LockTimeout, bootstrap_lock

    ready = False
    try:
        with bootstrap_lock(timeout=BOOTSTRAP_LOCK_TIMEOUT):
            # 拿到锁后再复查一次：等锁的这段时间里，别人可能已经装好了
            if venv_py.exists() and deps_ok(venv_py):
                ready = True
            else:
                base = find_base_python()
                if not base:
                    raise PythonTooOldError(
                        "当前 Python 版本低于 3.9，且系统里没有找到更新的版本"
                    )
                if not _create_venv(base):
                    raise RuntimeError_(f"创建虚拟环境失败：{paths.venv_dir()}")
                problem = _install(venv_py)
                if problem:
                    raise RuntimeError_(problem)
                ready = True
    except LockTimeout:
        raise RuntimeError_(
            "另一个 sshhh 进程正在首次准备运行环境（建虚拟环境 + 装依赖），"
            f"请等它结束再重试；锁文件：{paths.bootstrap_lock_file()}"
        ) from None

    if ready:
        _reexec(venv_py)
