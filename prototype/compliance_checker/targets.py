"""Targets: HOW the scanner reaches a host (local folder, SSH, WinRM, saved JSON).

Collectors never open files or connections themselves. They ask a target to
read a file or run a fixed read-only command, so the same collector code works
on a saved snapshot (tests, demo), the local machine, or a VM over the network.

Linux targets offer: read_text(path), list_dir(path), file_mode(path), run(cmd).
Windows targets offer: collect_raw() -> {snippet_name: parsed JSON}.

SECURITY: every command a target runs comes from this codebase, never from the
inventory file or the web page, and every command is read-only (REQ-07).
"""
from __future__ import annotations

import json
import os
import re
import shlex
import stat
import subprocess
from pathlib import Path
from typing import Any


class TargetError(RuntimeError):
    """The host could not be reached or logged in to. Shown on the dashboard."""


def _slug(command: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", command.lower()).strip("_")


# ----------------------------------------------------------------------------- Linux

# WHAT: A Linux filesystem on this machine: "/" (live) or a snapshot folder.
# WHY: snapshot folders let us test and demo without a VM. A snapshot stores
# command output in _commands/<slug>.txt, e.g. _commands/systemctl_is_active_auditd.txt
class LocalTarget:
    def __init__(self, root: str | Path = "/"):
        self.root = Path(root)
        self.live = self.root.resolve() == Path("/")
        self.description = "this machine" if self.live else f"snapshot {self.root}"

    def _p(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def read_text(self, path: str) -> str | None:
        p = self._p(path)
        try:
            return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else None
        except OSError:  # e.g. permission denied on /etc/shadow without sudo
            return None

    def list_dir(self, path: str) -> list[str]:
        p = self._p(path)
        return sorted(x.name for x in p.iterdir()) if p.is_dir() else []

    def file_mode(self, path: str) -> str | None:
        p = self._p(path)
        if not p.exists():
            return None
        # WHY: Git does not keep file permissions (only the execute bit), so a
        # snapshot records the real modes in _modes.txt as "<path> <mode>" lines.
        if not self.live:
            for line in (self.read_text("_modes.txt") or "").splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0] == path:
                    return parts[1].zfill(4)
        return format(stat.S_IMODE(os.stat(p).st_mode), "04o")

    def run(self, command: str) -> str | None:
        if not self.live:
            out = self.read_text(f"_commands/{_slug(command)}.txt")
            return out.strip() if out and out.strip() else None
        try:
            proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            return None
        # WHY: keep stdout even on a non-zero exit code: `systemctl is-active x`
        # prints "inactive" and exits 3, and "inactive" is the answer we need.
        return proc.stdout.strip() or None

    # WHAT: Write a file for a script scan (see script_scan.py). Live targets only.
    # SECURITY: the folder is created 0700 so no other local user can swap the script.
    def put_text(self, path: str, text: str, *, mode: int = 0o700,
                 private_dir: str | None = None) -> None:
        if not self.live:
            raise TargetError("a snapshot folder cannot run a script scan")
        if private_dir:
            Path(private_dir).mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(private_dir, 0o700)
        p = Path(path)
        p.write_text(text, encoding="utf-8")
        os.chmod(p, mode)

    # WHAT: Run a scanner script as root on this machine and return (rc, stdout, stderr).
    def run_script(self, path: str, *, timeout: int = 300) -> tuple[int, str, str]:
        if not self.live:
            raise TargetError("a snapshot folder cannot run a script scan")
        command = f"bash {shlex.quote(path)}" if os.geteuid() == 0 else \
            f"sudo -n bash {shlex.quote(path)}"
        try:
            proc = subprocess.run(command, shell=True, capture_output=True, text=True,
                                  timeout=timeout)
        except subprocess.TimeoutExpired:
            raise TargetError(f"the scan script timed out after {timeout}s") from None
        except OSError as exc:
            raise TargetError(f"could not run the scan script: {exc}") from exc
        return proc.returncode, proc.stdout, proc.stderr

    def close(self) -> None:
        pass


# WHAT: A Linux VM reached over SSH (agentless).
# SECURITY: password/key come from environment variables named in the inventory,
# never from the inventory file itself, and are never logged or stored.
class SSHTarget:
    def __init__(self, address: str, username: str, *, port: int = 22,
                 password: str | None = None, key_file: str | None = None,
                 use_sudo: bool = False, accept_unknown_host_key: bool = False,
                 timeout: int = 10):
        try:
            import paramiko
        except ImportError as exc:  # optional dependency, only needed for remote Linux scans
            raise TargetError("SSH scans need paramiko: pip install paramiko") from exc
        self.description = f"ssh {username}@{address}:{port}"
        self.use_sudo = use_sudo
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        # SECURITY: by default refuse hosts that are not in known_hosts (stops a
        # fake VM from collecting our password). The lab may opt in to trust on first use.
        self.client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy() if accept_unknown_host_key else paramiko.RejectPolicy())
        try:
            self.client.connect(address, port=port, username=username, password=password,
                                key_filename=key_file, timeout=timeout,
                                allow_agent=key_file is None and password is None,
                                look_for_keys=key_file is None and password is None)
        except Exception as exc:
            raise TargetError(f"SSH connection to {address}:{port} failed: "
                              f"{type(exc).__name__}: {exc}") from exc

    def _exec(self, command: str, sudo: bool) -> tuple[int, str]:
        # WHY: `sudo -n` never prompts; if passwordless sudo is not set up it just fails,
        # and the fact becomes NOT_COLLECTED instead of the scan hanging.
        if sudo and self.use_sudo:
            command = "sudo -n " + command
        _, stdout, _ = self.client.exec_command(command, timeout=30)
        out = stdout.read().decode("utf-8", errors="replace")
        return stdout.channel.recv_exit_status(), out

    def read_text(self, path: str) -> str | None:
        rc, out = self._exec(f"cat -- {shlex.quote(path)}", sudo=True)
        return out if rc == 0 else None

    def list_dir(self, path: str) -> list[str]:
        rc, out = self._exec(f"ls -1A -- {shlex.quote(path)}", sudo=True)
        return sorted(out.split()) if rc == 0 else []

    def file_mode(self, path: str) -> str | None:
        rc, out = self._exec(f"stat -c %a -- {shlex.quote(path)}", sudo=False)
        return out.strip().zfill(4) if rc == 0 and out.strip() else None

    def run(self, command: str) -> str | None:
        _, out = self._exec(command, sudo=True)
        return out.strip() or None

    # WHAT: Upload a scanner script to the VM (see script_scan.py).
    # SECURITY: the folder is made 0700 and owned by the scanning account, so a
    # local user on the VM cannot replace the script between upload and run.
    def put_text(self, path: str, text: str, *, mode: int = 0o700,
                 private_dir: str | None = None) -> None:
        try:
            if private_dir:
                self._exec(f"rm -rf -- {shlex.quote(private_dir)} && "
                           f"mkdir -m 700 -p -- {shlex.quote(private_dir)}", sudo=False)
            sftp = self.client.open_sftp()
            try:
                with sftp.file(path, "w") as fh:
                    fh.write(text)
                sftp.chmod(path, mode)
            finally:
                sftp.close()
        except Exception as exc:
            raise TargetError(f"could not copy the scan script to {self.description}: "
                              f"{type(exc).__name__}: {exc}") from exc

    # WHAT: Run the uploaded script as root and return (exit code, stdout, stderr).
    # WHY: separate from run(), because a script scan needs stderr and the exit
    # code to explain a sudo refusal instead of showing an empty scan.
    def run_script(self, path: str, *, timeout: int = 300) -> tuple[int, str, str]:
        command = f"sudo -n bash {shlex.quote(path)}" if self.use_sudo else \
            f"bash {shlex.quote(path)}"
        try:
            _, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            return stdout.channel.recv_exit_status(), out, err
        except Exception as exc:
            raise TargetError(f"running the scan script on {self.description} failed: "
                              f"{type(exc).__name__}: {exc}") from exc

    def close(self) -> None:
        self.client.close()


# ----------------------------------------------------------------------------- Windows

# WHAT: A Windows collector output saved as JSON (offline mode / demo / tests).
# WHY: if WinRM is blocked, run collect_windows.ps1 on the VM, copy the JSON back,
# and scan that. Also accepts a raw `secedit /export` .inf for the old workflow.
class WindowsFileTarget:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.description = f"file {self.path}"

    def collect_raw(self) -> dict[str, Any]:
        raw = self.path.read_bytes()
        # WHY: secedit and PowerShell 5 write UTF-16 with a BOM; hand-made files are UTF-8.
        text = (raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff")
                else raw.decode("utf-8-sig"))
        if self.path.suffix.lower() == ".inf":
            return {"secpol": {"inf": text}}
        return json.loads(text)

    def close(self) -> None:
        pass


# WHAT: A Windows 11 VM reached over WinRM (PowerShell remoting, agentless).
# ASSUMPTION: WinRM is enabled on the VM (`Enable-PSRemoting -Force`) and the account
# is a local administrator; secedit, auditpol and BitLocker need admin rights.
class WinRMTarget:
    def __init__(self, address: str, username: str, password: str, *,
                 port: int | None = None, use_https: bool = False,
                 transport: str = "ntlm", verify_tls: bool = True):
        try:
            import winrm
        except ImportError as exc:
            raise TargetError("WinRM scans need pywinrm: pip install pywinrm") from exc
        scheme = "https" if use_https else "http"
        port = port or (5986 if use_https else 5985)
        self.description = f"winrm {username}@{address}:{port}"
        # SECURITY: over plain http, NTLM still encrypts the message body
        # (pywinrm message_encryption="auto"). HTTPS with a real cert is better (T-21).
        self.session = winrm.Session(
            f"{scheme}://{address}:{port}/wsman", auth=(username, password),
            transport=transport,
            server_cert_validation="validate" if verify_tls else "ignore",
            operation_timeout_sec=60, read_timeout_sec=90)
        self.address = address

    def collect_raw(self) -> dict[str, Any]:
        from .windows_ps import SNIPPETS
        raw: dict[str, Any] = {}
        for name, script in SNIPPETS.items():
            try:
                res = self.session.run_ps(script)
            except Exception as exc:
                if not raw:  # first call failed: the host is unreachable or login is wrong
                    raise TargetError(f"WinRM connection to {self.address} failed: "
                                      f"{type(exc).__name__}: {exc}") from exc
                raw[name] = {"_error": f"{type(exc).__name__}: {exc}"}
                continue
            out = res.std_out.decode("utf-8", errors="replace").strip()
            try:
                raw[name] = json.loads(out) if out else {"_error": "no output"}
            except json.JSONDecodeError:
                raw[name] = {"_error": f"bad JSON: {out[:200]}"}
        return raw

    def close(self) -> None:
        pass
