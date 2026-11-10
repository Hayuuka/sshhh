"""SSH 传输层（paramiko）。

密码只作为局部变量在内存中传给 paramiko，连接结束即丢弃；
不出现在命令行参数、日志、异常信息里。
"""

from __future__ import annotations

import base64
import binascii
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


class _TOFU(paramiko.MissingHostKeyPolicy):
    def __init__(self) -> None:
        self.new_keys: list[tuple[str, paramiko.PKey]] = []

    def missing_host_key(self, client, hostname, key):
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
        text = path.read_text(encoding="utf-8")
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


def remember_host_keys(entries: list[tuple[str, paramiko.PKey]],
                       path: os.PathLike | str | None = None) -> bool:
    """记下新主机指纹：加锁 + 原子替换，失败返回 False。

    拿不到锁、写不进去都不能让本次执行失败（命令已经跑完了），但要让调用方
    有机会提示用户：没记下来的指纹，下次连接会重新走 TOFU。
    """
    if not entries:
        return True
    target = Path(path) if path is not None else paths.known_hosts_file()
    from .fsutil import atomic_write_text
    from .lock import LockTimeout, data_lock

    try:
        with data_lock(timeout=15):
            try:
                text = target.read_text(encoding="utf-8") if target.exists() else ""
            except OSError:
                text = ""
            atomic_write_text(target, merge_known_hosts(text, list(entries)))
        return True
    except (OSError, LockTimeout):
        return False


class Client:
    def __init__(self, host: Host, password: str | None,
                 settings: Settings | None = None,
                 redactor: Redactor | None = None):
        self.host = host
        self.settings = settings or Settings()
        self._password = password
        self.redactor = redactor or Redactor()
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
        h = self.host
        s = self.settings
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
        }

        if h.key_file:
            kwargs["pkey"] = _load_key(os.path.expanduser(h.key_file))
        elif self._password:
            kwargs["password"] = self._password
        else:
            raise TransportError(f"主机 {h.name} 没有可用凭据")

        try:
            ssh.connect(**kwargs)
        except paramiko.AuthenticationException:
            raise TransportError(
                f"认证失败：{h.user}@{h.host}:{h.port}，请检查用户名或密码"
            ) from None
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
        self._save_new_keys()

    def _save_new_keys(self) -> None:
        if not self._tofu.new_keys:
            return
        entries = list(self._tofu.new_keys)
        if remember_host_keys(entries, self.settings.known_hosts):
            self._tofu.new_keys.clear()
            return
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

    def run(self, command: str, stdin_data: str | None = None,
            timeout: float | None = None, use_sudo: bool = False) -> Result:
        if self._ssh is None:
            raise TransportError("尚未连接")

        limit = timeout or self.settings.command_timeout
        started = time.monotonic()

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
        channel.settimeout(limit)
        try:
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=2) as pool:
                fut_out = pool.submit(_drain, stdout)
                fut_err = pool.submit(_drain, stderr)
                out = fut_out.result(timeout=limit + 10)
                err = fut_err.result(timeout=limit + 10)
            code = channel.recv_exit_status()
        except (socket.timeout, TimeoutError):
            try:
                channel.close()
            except Exception:
                pass
            raise TransportError(f"命令执行超时（{limit}s），已中断") from None
        except TransportError:
            raise
        except Exception as exc:
            raise TransportError(f"读取输出失败：{self.redactor.clean(str(exc))}") from None

        return Result(
            stdout=self.redactor.clean(out),
            stderr=self.redactor.clean(err),
            exit_code=code,
            duration_ms=int((time.monotonic() - started) * 1000),
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


def _drain(stream) -> str:
    return stream.read().decode("utf-8", "replace")


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


def _load_key(path: str):
    errors = []
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key_file(path)
        except Exception as exc:
            errors.append(f"{cls.__name__}: {exc}")
    raise TransportError(f"无法加载私钥 {path}")
