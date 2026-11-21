"""SSH 传输层（paramiko）。

密码只作为局部变量在内存中传给 paramiko，连接结束即丢弃；
不出现在命令行参数、日志、异常信息里。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko

from . import paths
from .redact import Redactor
from .store import Host, Settings


class TransportError(Exception):
    pass


@dataclass
class Result:
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    # 读取侧截断（#40）：远端输出超过读取预算，只读回了预算内的部分。
    # 与 output.shape 的回传截断不同 —— 那是读完之后整形，这是读完
    # 之前就停止了接收，原始总量从此不可知。
    stdout_read_truncated: bool = False
    stderr_read_truncated: bool = False


class _TOFU(paramiko.MissingHostKeyPolicy):
    def __init__(self) -> None:
        self.new_keys: list[tuple[str, paramiko.PKey]] = []

    def missing_host_key(self, client, hostname, key):
        # 密钥优先登录会先试一次密钥再回落密码（#3）：两次握手都会走到这里，
        # 同一台主机的指纹只记一次，避免 known_hosts 里写重行
        for h, k in self.new_keys:
            if h == hostname and k.get_base64() == key.get_base64():
                return
        self.new_keys.append((hostname, key))


# --------------------------------------------------------------------------
# known_hosts（TOFU 指纹库）
# --------------------------------------------------------------------------


def _key_line(hostname: str, key: paramiko.PKey) -> str:
    return f"{hostname} {key.get_name()} {key.get_base64()}"


def merge_known_hosts(text: str, entries: list[tuple[str, paramiko.PKey]]) -> str:
    """把新指纹并进 known_hosts 文本，只动这些主机自己的条目。

    原先每次首连都用 `HostKeys.save()` 整文件重写：并发首连时后写的覆盖先写
    的，写一半崩掉还能留下截断文件，而截断文件下次被 `except: pass` 吞掉后
    「谁都被信任」（#31）。这里改成按主机名替换行，其它主机与注释原样保留。
    """
    by_host: dict[str, list[str]] = {}
    for hostname, key in entries:
        by_host.setdefault(hostname, []).append(_key_line(hostname, key))

    kept: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            kept.append(line)
            continue
        fields = stripped.split()
        if fields and fields[0] in by_host:
            continue  # 这台主机的旧条目整体替换掉
        kept.append(line)

    while kept and not kept[-1].strip():
        kept.pop()
    for hostname, lines in by_host.items():
        kept.extend(lines)
    return "\n".join(kept) + "\n" if kept else ""


def check_known_hosts_text(text: str) -> tuple[int, str] | None:
    """返回第一条结构性损坏的行 (行号, 内容)，全部正常返回 None。

    为什么要自己看：`paramiko.HostKeys.load()` 对解析不了的行**静默跳过**。
    文件被写坏一半时它不报错，只是加载出一份更短的指纹库；极端情况下一行都
    没加载成功，于是「严格校验」变成「任何主机密钥都接受」——这正是 #31 里
    那条静默降级链的起点。这里只查结构（字段数、base64 是否可解），不判密钥
    类型，避免把合法的冷门 key type 误判成损坏。
    """
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        # 带标记的行（@cert-authority / @revoked）多一个字段在前
        has_marker = fields[0].startswith("@")
        need = 4 if has_marker else 3
        if len(fields) < need:
            return lineno, stripped
        blob = fields[3] if has_marker else fields[2]
        if len(blob) < 32:
            return lineno, stripped
        try:
            base64.b64decode(blob, validate=True)
        except (ValueError, binascii.Error):
            return lineno, stripped
    return None


def load_known_hosts(ssh: paramiko.SSHClient, path: Path) -> None:
    """把指纹库装进 client；文件损坏就抛错，绝不静默当作空库继续。

    抛 TransportError → CLI 侧映射成 EXIT_NETWORK(4)，并且发生在认证之前，
    不会把凭据发给一台「校验不了」的机器。
    """
    try:
        from .fsutil import read_text as _read
        text = _read(path)
    except (OSError, UnicodeDecodeError) as exc:
        raise TransportError(
            f"主机指纹库损坏，无法校验目标主机：{path}\n（{exc}）\n"
            "连接已中止，没有向该主机发送任何凭据。请让用户确认如何处理该文件。"
        ) from None

    bad = check_known_hosts_text(text)
    if bad is not None:
        raise TransportError(
            f"主机指纹库损坏，无法校验目标主机：{path}\n"
            f"（第 {bad[0]} 行无法解析：{bad[1][:80]}）\n"
            "连接已中止，没有向该主机发送任何凭据。请让用户确认这个文件为什么坏了："
            "修好可保留原有指纹；确认要重来则删除它（之后首次连接会重新记录指纹）。"
        )

    try:
        ssh.load_host_keys(str(path))
    except Exception as exc:  # noqa: BLE001
        raise TransportError(
            f"主机指纹库载入失败：{path}\n（{exc}）\n"
            "连接已中止，没有向该主机发送任何凭据。请让用户确认如何处理该文件。"
        ) from None


def _hostkey_fingerprint(key: paramiko.PKey) -> str:
    """OpenSSH 风格的 SHA256 指纹（无填充），与 `ssh-keygen -lf` 一致。"""
    digest = hashlib.sha256(key.asbytes()).digest()
    return base64.b64encode(digest).decode("ascii").rstrip("=")


def remember_host_keys(entries: list[tuple[str, paramiko.PKey]],
                       path: os.PathLike | str | None = None) -> bool:
    """记下新主机指纹：加锁 + 原子替换，失败返回 False。

    拿不到锁、写不进去都不能让本次执行失败（命令已经跑完了），但要让调用方
    有机会提示用户：没记下来的指纹，下次连接会重新走 TOFU。
    """
    if not entries:
        return True
    target = Path(path) if path is not None else paths.known_hosts_file()
    from .fsutil import atomic_write_text, read_text
    from .lock import LockTimeout, data_lock

    try:
        with data_lock(timeout=15):
            try:
                text = read_text(target) if target.exists() else ""
            except OSError:
                text = ""
            atomic_write_text(target, merge_known_hosts(text, list(entries)))
        return True
    except (OSError, LockTimeout):
        return False


class Client:
    def __init__(self, host: Host, password: str | None,
                 settings: Settings | None = None,
                 redactor: Redactor | None = None,
                 key_pem: str | None = None):
        self.host = host
        self.settings = settings or Settings()
        self._password = password
        self._key_pem = key_pem
        self.redactor = redactor or Redactor()
        # 实际使用的认证方式与回落标记（#3）：连接成功后由 CLI 层写进审计。
        # auth_used 取值 "key" / "password"；auth_fallback 表示密钥认证
        # 被拒后回落到了密码 —— 设计要求这个回落必须可见（防加固被静默
        # 移除后无人察觉）。
        self.auth_used: str = ""
        self.auth_fallback: bool = False
        self._ssh: paramiko.SSHClient | None = None
        self._sftp: paramiko.SFTPClient | None = None
        self._tofu = _TOFU()

    def __enter__(self) -> "Client":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- 连接 ----------------------------------------------------------

    def connect(self) -> None:
        """连接主机。认证编排（#3 基线）：vault 密钥优先，密码兜底。

        key_file 字段不再参与认证（#18）：hosts.toml 对 agent 可写，磁盘
        路径上的私钥等于一个不经密码库的托管旁路 —— agent 可以用它连上
        任何自己的服务器，审计里只留一条正常记录。认证材料只来自 vault
        （key:<host> 与密码条目），两者都没有时给出迁移指引而不是静默失败。
        """
        h = self.host
        s = self.settings

        attempts: list[tuple[str, dict]] = []
        if self._key_pem:
            attempts.append(("key", {"pkey": _pkey_from_pem(self._key_pem)}))
        if self._password:
            attempts.append(("password", {"password": self._password}))
        if not attempts:
            if h.key_file:
                raise TransportError(
                    f"主机 {h.name} 只配置了已废弃的 key_file 字段"
                    "（#18 之后不再从磁盘路径认证）。"
                    "请在你的终端执行：sshhh manage keyimport "
                    f"{h.name}（会自动使用该字段记录的路径）"
                )
            raise TransportError(f"主机 {h.name} 没有可用凭据")

        saw_key_attempt = bool(self._key_pem)
        last_auth_error: TransportError | None = None
        for method, creds in attempts:
            # 每次尝试用全新 client：认证失败后重连要重走完整的握手与
            # 指纹校验，不能复用已经出过 AuthenticationException 的传输层
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(self._tofu)
            known = s.known_hosts
            if known.exists():
                load_known_hosts(ssh, known)

            kwargs: dict = {
                "hostname": h.host,
                "port": h.port,
                "username": h.user,
                "timeout": s.connect_timeout,
                "banner_timeout": s.connect_timeout,
                "auth_timeout": s.connect_timeout,
                "allow_agent": False,
                "look_for_keys": False,
                **creds,
            }
            try:
                ssh.connect(**kwargs)
            except paramiko.AuthenticationException as exc:
                last_auth_error = TransportError(
                    f"认证失败：{h.user}@{h.host}:{h.port}"
                    + ("，密钥认证被服务器拒绝" if method == "key"
                       else "，请检查用户名或密码"))
                if method == "key" and self._password:
                    continue  # 密钥被拒 → 回落到密码（auth_fallback 留痕）
                raise last_auth_error from None
            except paramiko.SSHException as exc:
                msg = self.redactor.clean(str(exc))
                if "not found in known_hosts" in msg or "Host key" in msg:
                    raise TransportError(f"主机密钥校验失败：{msg}") from None
                raise TransportError(f"SSH 错误：{msg}") from None
            except (socket.timeout, TimeoutError):
                raise TransportError(f"连接超时：{h.host}:{h.port}") from None
            except OSError as exc:
                raise TransportError(f"网络错误：{exc}") from None

            self._ssh = ssh
            self.auth_used = method
            self.auth_fallback = (method == "password" and saw_key_attempt)
            self._save_new_keys()
            return
        raise last_auth_error or TransportError("认证失败：无可用的认证方式")

    def _save_new_keys(self) -> None:
        if not self._tofu.new_keys:
            return
        entries = list(self._tofu.new_keys)
        recorded = remember_host_keys(entries, self.settings.known_hosts)
        if recorded:
            self._tofu.new_keys.clear()
        # 首连的 TOFU 窗口是本地防不住的弱点（#31 / TM-A6）：把指纹放进一行
        # 机器可读的状态行，agent 在首次连接时把它念给用户，让用户有机会
        # 当场发现「连错了机器」。这行出现在任何远端输出之前，是权威值；
        # 远端在后续连接里伪造同型行只会造成一次多余的播报。
        for hostname, key in entries:
            try:
                sys.stderr.write(
                    f"SSHHH_HOSTKEY: SHA256:{_hostkey_fingerprint(key)}"
                    f"（首次连接 {hostname}，指纹已记录到 "
                    f"{self.settings.known_hosts}）\n"
                )
            except Exception:
                pass
        if not recorded:
            # 记不下来不让本次执行失败（命令已经跑完、输出就在内存里），但要说出来：
            # 这台主机的指纹没进库，下次连接会重新走 TOFU。
            try:
                sys.stderr.write(
                    f"[sshhh] 警告：没能记录主机指纹（{self.settings.known_hosts}），"
                    "下次连接将重新校验该主机指纹\n"
                )
            except Exception:
                pass

    # -- 执行 ----------------------------------------------------------

    def banner(self) -> str:
        """远端版本 banner（如 `SSH-2.0-OpenSSH_9.6p1`），取不到返回空串。

        用于 harden --check 判断 sshd 是否 OpenSSH：不用在服务器上执行任何
        命令，握手阶段就能拿到（#37）。
        """
        if self._ssh is None:
            raise TransportError("尚未连接")
        try:
            t = self._ssh.get_transport()
            return ((t.get_banner() or b"") if t else b"").decode(
                "utf-8", "replace").strip()
        except Exception:
            return ""

    def run(self, command: str, stdin_data: str | None = None,
            timeout: float | None = None, use_sudo: bool = False,
            max_bytes: int | None = None) -> Result:
        """执行命令。`timeout` 是墙钟上限（#40）：不管远端说不说话、
        说不说完，到点就中断。`max_bytes` 给读取侧封顶（每条流读够
        `max_bytes * _READ_BUDGET_FACTOR` 就停止接收），远端刷再多的
        输出也不会把客户端内存灌爆。"""
        if self._ssh is None:
            raise TransportError("尚未连接")

        limit = timeout or self.settings.command_timeout
        started = time.monotonic()
        deadline = started + limit

        if use_sudo:
            command = f"sudo -S -p '' bash -lc {_shquote(command)}"
            # `sudo -S` 把 stdin 的第一行当密码。调用方自己喂的数据必须排在
            # 后面，否则 sudo 会拿它当密码去认证，命令根本跑不起来。
            stdin_data = (self._password or "") + "\n" + (stdin_data or "")

        try:
            stdin, stdout, stderr = self._ssh.exec_command(
                command, timeout=limit, get_pty=False
            )
        except paramiko.SSHException as exc:
            raise TransportError(f"执行失败：{self.redactor.clean(str(exc))}") from None

        if stdin_data:
            try:
                stdin.write(stdin_data)
                stdin.channel.shutdown_write()
            except Exception:
                pass

        channel = stdout.channel
        # 单次 recv 的阻塞粒度压到 1 秒（stdin 已写完，不会再受影响）：
        # 总时长约束靠 deadline 检查，而不是「单次 recv 超过 channel
        # timeout」—— 远端持续产出时后者永远不触发（#40）
        channel.settimeout(_RECV_SLICE)

        out_budget = err_budget = None
        if max_bytes is not None and max_bytes > 0:
            # 读取预算取回传上限的数倍：output.shape 的头尾整形（TM-A4）
            # 在这个量级内仍然成立，超出就直接停止接收，内存有硬顶
            out_budget = max_bytes * _READ_BUDGET_FACTOR
            err_budget = max_bytes * _READ_BUDGET_FACTOR

        out = err = b""
        out_reason = err_reason = "eof"
        hung = False
        try:
            from concurrent.futures import ThreadPoolExecutor
            from concurrent.futures import wait as futures_wait

            with ThreadPoolExecutor(max_workers=2) as pool:
                fut_out = pool.submit(_drain_channel, channel, deadline,
                                      out_budget, stderr=False)
                fut_err = pool.submit(_drain_channel, channel, deadline,
                                      err_budget, stderr=True)
                # _drain_channel 会按 deadline / 预算自行收束，这里只等
                # 结果。不能用 fut.result(timeout=...)：到点抛异常后 with
                # 的 __exit__ 还要先等线程结束，持续输出的远端让它永远
                # 等不到 —— 旧实现的挂死根源（#40）。
                futures_wait({fut_out, fut_err}, timeout=limit + 30)
                hung = any(not f.done() for f in (fut_out, fut_err))
                if hung:
                    # 理论上到不了（线程自按 deadline 结束）；万一卡在
                    # 阻塞 recv 里，先关通道让 recv 立刻失败再收尸
                    try:
                        channel.close()
                    except Exception:
                        pass
                    futures_wait([f for f in (fut_out, fut_err)
                                  if not f.done()], timeout=10)
                if fut_out.done():
                    out, out_reason = fut_out.result()
                if fut_err.done():
                    err, err_reason = fut_err.result()

            if "deadline" in (out_reason, err_reason) or hung:
                try:
                    channel.close()
                except Exception:
                    pass
                raise TransportError(f"命令执行超时（{limit}s），已中断")

            # 退出状态按 deadline 轮询：recv_exit_status 本身没有超时
            # 语义，远端不发退出状态时会在那里挂死
            while not channel.exit_status_ready():
                if time.monotonic() >= deadline:
                    try:
                        channel.close()
                    except Exception:
                        pass
                    raise TransportError(f"命令执行超时（{limit}s），已中断")
                time.sleep(0.05)
            code = channel.recv_exit_status()
        except TransportError:
            raise
        except Exception as exc:
            raise TransportError(f"读取输出失败：{self.redactor.clean(str(exc))}") from None

        return Result(
            stdout=self.redactor.clean(out.decode("utf-8", "replace")),
            stderr=self.redactor.clean(err.decode("utf-8", "replace")),
            exit_code=code,
            duration_ms=int((time.monotonic() - started) * 1000),
            stdout_read_truncated=(out_reason == "budget"),
            stderr_read_truncated=(err_reason == "budget"),
        )

    def close(self) -> None:
        if self._sftp is not None:
            try:
                self._sftp.close()
            except Exception:
                pass
            self._sftp = None
        if self._ssh is not None:
            try:
                self._ssh.close()
            except Exception:
                pass
            self._ssh = None
        self._password = None
        # 私钥 PEM 同样随连接结束消失（宪法：密钥材料内存即焚）
        self._key_pem = None

    # -- 文件通道 ------------------------------------------------------

    def sftp(self) -> paramiko.SFTPClient:
        """取（并缓存）SFTP 客户端。调用方不再直接摸 `_ssh`。"""
        if self._ssh is None:
            raise TransportError("尚未连接")
        if self._sftp is None:
            try:
                self._sftp = self._ssh.open_sftp()
            except Exception as exc:  # noqa: BLE001
                raise TransportError(
                    f"SSH 连接已建立，但打不开 SFTP 子系统："
                    f"{self.redactor.clean(str(exc))}"
                ) from None
        return self._sftp

    def get_file(self, remote: str, local: str, *,
                 max_bytes: int | None = None,
                 timeout: float | None = None) -> int:
        """下载，返回写入的字节数。超过上限或超时抛 TransportError。"""
        cap = self.settings.transfer_max_bytes if max_bytes is None else max_bytes
        limit = (self.settings.transfer_timeout if timeout is None else timeout)
        sftp = self.sftp()
        try:
            st = sftp.stat(remote)
        except OSError as exc:
            raise TransportError(f"读不到远端文件 {remote}：{exc}") from None
        size = int(getattr(st, "st_size", 0) or 0)
        if cap > 0 and size > cap:
            raise TransportError(
                f"远端文件 {remote} 有 {_human(size)}，超过单次传输上限 "
                f"{_human(cap)}。确认要传请加 --max-bytes {max(0, size)}"
            )

        deadline = time.monotonic() + limit if limit > 0 else None
        _arm_channel(sftp, limit)
        total = 0
        try:
            with sftp.open(remote, "rb") as src, open(local, "wb") as dst:
                while True:
                    chunk = src.read(_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if cap > 0 and total > cap:
                        raise TransportError(
                            f"远端文件 {remote} 超过单次传输上限 {_human(cap)}"
                            f"（已读 {_human(total)}），已中止。确认要传请加 "
                            f"--max-bytes {total}"
                        )
                    dst.write(chunk)
                    _check_deadline(deadline, "下载", remote)
        except BaseException:
            # 半截文件比没有更危险：读它的人会当真
            try:
                os.unlink(local)
            except OSError:
                pass
            raise
        return total

    def put_file(self, local: str, remote: str, *,
                 max_bytes: int | None = None,
                 timeout: float | None = None) -> int:
        """上传，返回发送的字节数。超过上限或超时抛 TransportError。"""
        cap = self.settings.transfer_max_bytes if max_bytes is None else max_bytes
        limit = (self.settings.transfer_timeout if timeout is None else timeout)
        try:
            size = os.path.getsize(local)
        except OSError as exc:
            raise TransportError(f"读不到本地文件 {local}：{exc}") from None
        if cap > 0 and size > cap:
            raise TransportError(
                f"本地文件 {local} 有 {_human(size)}，超过单次传输上限 "
                f"{_human(cap)}。确认要传请加 --max-bytes {max(0, size)}"
            )

        sftp = self.sftp()
        deadline = time.monotonic() + limit if limit > 0 else None
        _arm_channel(sftp, limit)
        total = 0
        try:
            with open(local, "rb") as src, sftp.open(remote, "wb") as dst:
                while True:
                    chunk = src.read(_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if cap > 0 and total > cap:
                        raise TransportError(
                            f"本地文件 {local} 超过单次传输上限 {_human(cap)}，已中止"
                        )
                    dst.write(chunk)
                    _check_deadline(deadline, "上传", remote)
        except BaseException:
            # 远端半截文件同样会被人当真，尽力删掉
            try:
                sftp.remove(remote)
            except Exception:
                pass
            raise
        return total


def _drain_channel(channel, deadline: float | None, budget: int | None,
                   *, stderr: bool) -> tuple[bytes, str]:
    """读一条流直到 EOF / 到 deadline / 读满预算，返回 (数据, 停止原因)。

    停止原因：eof（读尽）/ deadline（到墙钟上限）/ budget（读满预算）/
    closed（通道被关闭）。

    旧实现 stream.read() 只有「单次 recv 超过 channel timeout」一个退出
    条件：总时长与总量都没有约束 —— 远端每 0.1 秒来一条数据，单次 recv
    就永远不会超时，命令永不返回；远端刷 1 GB 输出，内存就涨 1 GB（#40）。
    现在每拿到一块数据都先看墙钟，总量另有预算封顶。
    """
    recv = channel.recv_stderr if stderr else channel.recv
    chunks: list[bytes] = []
    total = 0
    while True:
        if deadline is not None and time.monotonic() >= deadline:
            return b"".join(chunks), "deadline"
        if budget is not None and total >= budget:
            return b"".join(chunks), "budget"
        try:
            data = recv(_RUN_CHUNK)
        except socket.timeout:
            continue  # 单次等待超时不是结束，回循环顶看 deadline
        except EOFError:
            return b"".join(chunks), "eof"
        except OSError:
            # 通道被关闭（对端断开，或超时收尾时主线程关了通道）
            return b"".join(chunks), "closed"
        if not data:
            return b"".join(chunks), "eof"
        chunks.append(data)
        total += len(data)


# run 的输出读取（#40）：单次 recv 的阻塞粒度（秒）与单块读取字节数
_RECV_SLICE = 1.0
_RUN_CHUNK = 8 * 1024
# 每条流的读取预算 = 回传上限 × 此倍数：给 output.shape 的头尾整形留材料
_READ_BUDGET_FACTOR = 4


# 文件通道的分块大小与上限说明，见 Settings.transfer_max_bytes
_CHUNK = 32 * 1024


def _human(size: int) -> str:
    if size >= 1024 * 1024 * 1024:
        return f"{size / (1024 ** 3):.1f} GiB"
    if size >= 1024 * 1024:
        return f"{size / (1024 ** 2):.1f} MiB"
    if size >= 1024:
        return f"{size / 1024:.1f} KiB"
    return f"{size} 字节"


def _arm_channel(sftp: paramiko.SFTPClient, limit: float) -> None:
    """把超时压到 SFTP 通道上，避免对端不发数据时无限挂住。"""
    if limit <= 0:
        return
    try:
        channel = sftp.get_channel()
        if channel is not None:
            channel.settimeout(limit)
    except Exception:
        pass


def _check_deadline(deadline: float | None, what: str, target: str) -> None:
    if deadline is not None and time.monotonic() > deadline:
        raise TransportError(f"{what}超时：{target} 传输时间超过上限，已中止")


def _shquote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _pkey_from_pem(pem: str) -> paramiko.PKey:
    """把 vault 里的私钥 PEM 加载成内存中的 PKey。

    私钥材料只在内存里流转（设计宪法）：不读文件、不落盘。归一化在导入时
    已做过（lib.sshkeys.normalize_pem），这里只负责加载；加载失败多半是
    vault 里的条目被改坏，报错要让用户看得出该重新导入。
    """
    from .sshkeys import SSHKeyError, load_pkey

    try:
        return load_pkey(pem)
    except SSHKeyError as exc:
        raise TransportError(
            f"加载密钥失败（可用 manage keyimport 重新导入）：{exc}"
        ) from None
