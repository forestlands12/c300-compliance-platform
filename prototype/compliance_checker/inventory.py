"""Inventory: the list of playground hosts to scan (inventory/*.yaml).

SECURITY: the inventory never holds passwords. It names the ENVIRONMENT
VARIABLE that holds each secret (password_env), so the file can live in Git.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .targets import LocalTarget, SSHTarget, TargetError, WindowsFileTarget, WinRMTarget

TRANSPORTS = {
    "linux": ("snapshot", "local", "ssh"),
    "windows": ("file", "winrm"),
}
KINDS = ("pos", "office", "web", "db", "server")


class InventoryError(ValueError):
    pass


# WHAT: One host from the inventory file.
@dataclass
class Host:
    name: str
    platform: str
    transport: str
    role: str = ""
    kind: str = "server"
    services: tuple[str, ...] = ()
    address: str = ""
    port: int | None = None
    path: str = ""
    username: str = ""
    username_env: str = ""
    password_env: str = ""
    key_file: str = ""
    sudo: bool = False
    accept_unknown_host_key: bool = False
    use_https: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def tags(self) -> set[str]:
        return {self.platform, *self.services}

    @property
    def location(self) -> str:
        return self.address or self.path

    def _user(self) -> str:
        user = os.environ.get(self.username_env, "") if self.username_env else self.username
        if not user:
            raise TargetError(f"{self.name}: no username (set {self.username_env or 'username'})")
        return user

    def _secret(self) -> str | None:
        if not self.password_env:
            return None
        value = os.environ.get(self.password_env)
        if value is None:
            raise TargetError(f"{self.name}: environment variable {self.password_env} is not set")
        return value

    # WHAT: Open a connection (or folder) for this host. Raises TargetError if it cannot.
    def open(self):
        if self.transport in ("snapshot", "local"):
            root = "/" if self.transport == "local" else self.path
            if not Path(root).is_dir():
                raise TargetError(f"{self.name}: snapshot folder not found: {root}")
            return LocalTarget(root)
        if self.transport == "file":
            if not Path(self.path).is_file():
                raise TargetError(f"{self.name}: collector output not found: {self.path}")
            return WindowsFileTarget(self.path)
        if self.transport == "ssh":
            return SSHTarget(self.address, self._user(), port=self.port or 22,
                             password=self._secret(),
                             key_file=os.path.expanduser(self.key_file) if self.key_file else None,
                             use_sudo=self.sudo,
                             accept_unknown_host_key=self.accept_unknown_host_key)
        if self.transport == "winrm":
            password = self._secret()
            if password is None:
                raise TargetError(f"{self.name}: WinRM needs password_env")
            return WinRMTarget(self.address, self._user(), password,
                               port=self.port, use_https=self.use_https)
        raise TargetError(f"{self.name}: unknown transport {self.transport}")


# WHAT: The whole inventory file: organisation name plus hosts.
@dataclass
class Inventory:
    organisation: str
    environment: str
    hosts: list[Host]
    path: Path


def load_inventory(path: str | Path) -> Inventory:
    path = Path(path)
    # SECURITY: safe_load, never yaml.load.
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw_hosts = data.get("hosts")
    if not isinstance(raw_hosts, list) or not raw_hosts:
        raise InventoryError(f"{path}: expected a non-empty 'hosts:' list")
    hosts: list[Host] = []
    names: set[str] = set()
    for i, raw in enumerate(raw_hosts, start=1):
        for key in ("name", "platform", "transport"):
            if key not in raw:
                raise InventoryError(f"{path}: host #{i} is missing '{key}'")
        name, platform, transport = str(raw["name"]), raw["platform"], raw["transport"]
        if name in names:
            raise InventoryError(f"{path}: duplicate host name {name}")
        if platform not in TRANSPORTS:
            raise InventoryError(f"{path}: {name} has unknown platform '{platform}'")
        if transport not in TRANSPORTS[platform]:
            raise InventoryError(f"{path}: {name}: transport '{transport}' is not valid for "
                                 f"{platform} (use one of {', '.join(TRANSPORTS[platform])})")
        if "password" in raw:
            # SECURITY: refuse plain-text passwords so nobody commits one by accident.
            raise InventoryError(f"{path}: {name} has a plain 'password'. Use password_env instead.")
        kind = raw.get("kind", "server")
        if kind not in KINDS:
            raise InventoryError(f"{path}: {name} has unknown kind '{kind}' ({', '.join(KINDS)})")
        known = {f for f in Host.__dataclass_fields__ if f not in ("extra", "services")}
        args = {k: v for k, v in raw.items() if k in known}
        # WHY: paths in the inventory are relative to the inventory file, not to
        # wherever the user happened to start Python.
        if args.get("path"):
            args["path"] = str((path.parent / os.path.expanduser(str(args["path"]))).resolve())
        names.add(name)
        hosts.append(Host(**{**args, "name": name, "kind": kind},
                          services=tuple(raw.get("services") or ()),
                          extra={k: v for k, v in raw.items() if k not in known}))
    return Inventory(organisation=str(data.get("organisation", "SME Supermarket")),
                     environment=str(data.get("environment", "")),
                     hosts=hosts, path=path)
