"""SSH 传输层（paramiko）。

密码只作为局部变量在内存中传给 paramiko，连接结束即丢弃；
不出现在命令行参数、日志、异常信息里。
"""

from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass

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


class Client:
    def __init__(self, host: Host, password: str | None,
                 settings: Settings | None = None,
                 redactor: Redactor | None = None):
        self.host = host
        self.settings = settings or Settings()
        self._password = password
        self.redactor = redactor or Redactor()
        self._ssh: paramiko.SSHClient | None = None
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
            try:
                ssh.load_host_keys(str(known))
            except Exception:
                pass

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
        known = self.settings.known_hosts
        try:
            known.parent.mkdir(parents=True, exist_ok=True)
            keys = paramiko.HostKeys()
            if known.exists():
                keys.load(str(known))
            for hostname, key in self._tofu.new_keys:
                keys.add(hostname, key.get_name(), key)
            keys.save(str(known))
            self._tofu.new_keys.clear()
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
        if self._ssh is not None:
            try:
                self._ssh.close()
            except Exception:
                pass
            self._ssh = None
        self._password = None


def _drain(stream) -> str:
    return stream.read().decode("utf-8", "replace")


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
