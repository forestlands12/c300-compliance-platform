"""Collectors read raw OS configuration and turn it into normalised facts.

Every collector returns a flat dict of the SAME fact names (e.g.
"password.min_length") whatever the OS, so one control can cover Linux and
Windows. Adding a new OS means adding a collector, not rewriting controls.

Collectors are read-only: they never change the target. They read through a
target object (see targets.py), so the same code scans a snapshot folder, this
machine, or a VM over SSH/WinRM.
"""
from __future__ import annotations

import configparser
import fnmatch
import posixpath
import re
from pathlib import Path
from typing import Any

from .targets import LocalTarget, WindowsFileTarget

# ASSUMPTION: these match current OpenSSH; older versions may differ. REF: man sshd_config
# OpenSSH defaults used when a directive is absent from sshd_config
# (see `man sshd_config`). Recorded so the report shows the effective value.
SSHD_DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "maxauthtries": "6",
}


# WHAT: Generic parser for Linux config text ('KEY value' or 'key = value').
def _parse_kv(text: str | None, sep: str | None = None) -> dict[str, str]:
    """Parse simple 'KEY value' or 'key = value' text, ignoring comments."""
    values: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if sep and sep in line:
            key, _, val = line.partition(sep)
        else:
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, val = parts
        # WHY: sshd uses the FIRST occurrence of a directive, so keep the first one.
        values.setdefault(key.strip().lower(), val.strip())
    return values


def _int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _glob(target, pattern: str) -> list[str]:
    folder, mask = posixpath.split(pattern)
    return [posixpath.join(folder, n) for n in target.list_dir(folder) if fnmatch.fnmatch(n, mask)]


# WHAT: Read sshd_config the way sshd does, following Include lines.
# FIX(B-02, 28 Oct 2026, Claude): v0.1 ignored "Include /etc/ssh/sshd_config.d/*.conf".
# Ubuntu 22.04+ puts settings there (cloud-init writes PasswordAuthentication),
# so the old parser could report the wrong effective value. Includes are now
# expanded in place; on SSH scans `sshd -T` (the real effective config) wins.
def _sshd_lines(target, path: str, depth: int = 0) -> list[str]:
    lines: list[str] = []
    for line in (target.read_text(path) or "").splitlines():
        words = line.split("#", 1)[0].split()
        if len(words) >= 2 and words[0].lower() == "include" and depth < 5:
            for pat in words[1:]:
                pat = pat if pat.startswith("/") else posixpath.join("/etc/ssh", pat)
                for inc in (_glob(target, pat) if any(c in pat for c in "*?[") else [pat]):
                    lines.extend(_sshd_lines(target, inc, depth + 1))
        else:
            lines.append(line)
    return lines


def _file_has_module(text: str | None, module: str) -> bool:
    return any(module in line.split("#", 1)[0] for line in (text or "").splitlines())


# WHAT: Turn Linux configuration into normalised facts (password, lockout, SSH,
# firewall, audit, updates, file permissions).
# SECURITY: read-only. Never write to the target (REQ-07).
def collect_linux_target(target) -> dict[str, Any]:
    facts: dict[str, Any] = {"os.family": "linux"}

    login_defs = _parse_kv(target.read_text("/etc/login.defs"))
    facts["password.max_age_days"] = _int(login_defs.get("pass_max_days"))
    facts["password.min_age_days"] = _int(login_defs.get("pass_min_days"))
    facts["password.min_length"] = _int(login_defs.get("pass_min_len"))

    # WHY: pam_pwquality overrides login.defs for minimum length on modern distros.
    pwquality = _parse_kv(target.read_text("/etc/security/pwquality.conf"), sep="=")
    if "minlen" in pwquality:
        facts["password.min_length"] = _int(pwquality["minlen"])

    faillock = _parse_kv(target.read_text("/etc/security/faillock.conf"), sep="=")
    facts["lockout.threshold"] = _int(faillock.get("deny"))
    unlock = _int(faillock.get("unlock_time"))
    # WHY: unlock_time is in seconds; 0 means "admin must unlock", which is stricter, so treat it as very long.
    facts["lockout.duration_minutes"] = None if unlock is None else (
        10**6 if unlock == 0 else unlock // 60)

    # WHY: faillock.conf alone does nothing unless pam_faillock is in the PAM stack
    # (closes the old TODO T-11). Debian/Ubuntu: common-auth; RHEL family: system-auth.
    pam_files = [target.read_text(p) for p in ("/etc/pam.d/common-auth", "/etc/pam.d/system-auth")]
    if any(t is not None for t in pam_files):
        facts["lockout.pam_enabled"] = any(_file_has_module(t, "pam_faillock.so") for t in pam_files)

    # SSH: prefer the effective config from `sshd -T` (needs root), else parse files.
    effective = target.run("sshd -T")
    if effective and "permitrootlogin" in effective.lower():
        sshd = _parse_kv(effective.lower())
    elif target.read_text("/etc/ssh/sshd_config") is not None:
        sshd = {**SSHD_DEFAULTS, **_parse_kv("\n".join(_sshd_lines(target, "/etc/ssh/sshd_config")))}
    else:
        sshd = {}
    if sshd:
        facts["ssh.permit_root_login"] = sshd.get("permitrootlogin", "").lower() or None
        facts["ssh.password_authentication"] = sshd.get("passwordauthentication", "").lower() or None
        facts["ssh.max_auth_tries"] = _int(sshd.get("maxauthtries"))

    mode = target.file_mode("/etc/shadow")
    if mode:
        facts["file.etc_shadow.mode"] = mode

    # Firewall: ufw (Ubuntu) or firewalld (RHEL family).
    ufw = target.read_text("/etc/ufw/ufw.conf")
    firewalld = target.run("systemctl is-active firewalld")
    if ufw is not None or firewalld is not None:
        facts["firewall.enabled"] = (_parse_kv(ufw, sep="=").get("enabled", "").strip("'\"").lower() == "yes"
                                     or firewalld == "active")

    auditd = target.run("systemctl is-active auditd")
    if auditd is not None:
        facts["audit.service_active"] = auditd == "active"

    # Automatic security updates: unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL).
    apt = target.read_text("/etc/apt/apt.conf.d/20auto-upgrades")
    dnf = target.run("systemctl is-active dnf-automatic.timer")
    if apt is not None or dnf is not None:
        facts["updates.automatic"] = bool(
            re.search(r'APT::Periodic::Unattended-Upgrade\s+"1"', apt or "")) or dnf == "active"
    return facts


# WHAT: Backwards-compatible wrapper: scan a local folder or "/" (v0.1 CLI and tests).
def collect_linux(root: str | Path = "/") -> dict[str, Any]:
    """Collect facts from a Linux filesystem rooted at `root`.

    root="/" scans the live machine; a folder path scans a saved snapshot
    (used for the samples and for tests).
    """
    return collect_linux_target(LocalTarget(root))


# ----------------------------------------------------------------------------- services

def _strip_hash_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


# WHAT: nginx (the online shop's web server) settings as normalised facts.
# ASSUMPTION: Debian/Ubuntu layout (/etc/nginx/nginx.conf, conf.d, sites-enabled).
# TODO(Ahmad, T-22): follow nginx `include` lines exactly instead of this fixed layout.
def collect_nginx(target) -> dict[str, Any]:
    main = target.read_text("/etc/nginx/nginx.conf")
    if main is None:
        return {"web.nginx_installed": False}
    texts = [main]
    for folder, mask in (("/etc/nginx/conf.d", "*.conf"), ("/etc/nginx/sites-enabled", "*")):
        for path in _glob(target, f"{folder}/{mask}"):
            texts.append(target.read_text(path) or "")
    conf = _strip_hash_comments("\n".join(texts))

    def values(directive: str) -> list[str]:
        # FIX(B-03, 28 Oct 2026, Claude): matched only directives at the start of a line,
        # so "location /images/ { autoindex on; }" on one line was missed and the
        # demo drift went unreported. Now a directive may also follow "{" or ";".
        return [m.group(1).strip() for m in
                re.finditer(rf"(?m)(?:^|[{{;}}])\s*{directive}\s+([^;{{}}]+);", conf)]

    tokens = values("server_tokens")
    protocols = " ".join(values("ssl_protocols")).split()
    https = any(re.search(r"\bssl\b", v) for v in values("listen")) or bool(values("ssl_certificate"))
    return {
        "web.nginx_installed": True,
        # REF: nginx docs, server_tokens defaults to "on" (version shown in errors and headers).
        "web.server_tokens": (tokens[-1] if tokens else "on").lower(),
        "web.autoindex_enabled": any(v.lower() == "on" for v in values("autoindex")),
        "web.https_enabled": https,
        # ASSUMPTION: no ssl_protocols line means nginx >= 1.23.4 defaults (TLSv1.2 + 1.3).
        "web.weak_tls_enabled": any(p in ("SSLv3", "TLSv1", "TLSv1.1") for p in protocols),
        "web.hsts_enabled": any("strict-transport-security" in v.lower() for v in values("add_header")),
    }


_MYSQL_FILES = ("/etc/mysql/my.cnf", "/etc/my.cnf")
_MYSQL_DIRS = ("/etc/mysql/conf.d", "/etc/mysql/mysql.conf.d", "/etc/mysql/mariadb.conf.d", "/etc/my.cnf.d")


def _on(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.strip().strip("'\"").lower() in ("1", "on", "true", "yes", "force_plus_permanent")


# WHAT: MySQL / MariaDB (the shop's customer and order database) settings as facts.
# WHY: config files only, so the scanner needs no database password.
# TODO(Ace, T-23): optionally read live values with SHOW VARIABLES for accuracy.
def collect_mysql(target) -> dict[str, Any]:
    paths = [p for p in _MYSQL_FILES if target.read_text(p) is not None]
    for folder in _MYSQL_DIRS:
        paths += _glob(target, f"{folder}/*.cnf")
    if not paths:
        return {"db.mysql_installed": False}
    server: dict[str, str] = {}
    for path in paths:
        section = ""
        for line in (target.read_text(path) or "").splitlines():
            line = line.split("#", 1)[0].split(";", 1)[0].strip()
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip().lower()
            elif line and section in ("mysqld", "mariadb", "server", "mariadbd"):
                key, _, val = line.partition("=")
                # WHY: MySQL treats bind-address and bind_address as the same option.
                # Later files override earlier ones, like the server does.
                server[key.strip().lower().replace("-", "_")] = val.strip() or "1"
    return {
        "db.mysql_installed": True,
        # ASSUMPTION: no bind-address means the upstream default "*" (all interfaces).
        "db.bind_address": server.get("bind_address", "*").strip("'\""),
        "db.local_infile": _on(server.get("local_infile")),
        # REF: require_secure_transport defaults to OFF in MySQL 8 and MariaDB.
        "db.secure_transport_required": bool(_on(server.get("require_secure_transport"))),
    }


SERVICE_COLLECTORS = {"nginx": collect_nginx, "mysql": collect_mysql}


# ----------------------------------------------------------------------------- Windows

# WHAT: Parse the text of a `secedit /export` file into password/lockout/guest facts.
def parse_secedit(text: str) -> dict[str, Any]:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str  # keep key case
    parser.read_string(text)
    sa = parser["System Access"] if parser.has_section("System Access") else {}

    def get(key: str) -> int | None:
        return _int(sa.get(key, "").strip()) if key in sa else None

    complexity = get("PasswordComplexity")
    reversible = get("ClearTextPassword")
    guest = get("EnableGuestAccount")
    return {
        "password.min_length": get("MinimumPasswordLength"),
        "password.max_age_days": get("MaximumPasswordAge"),
        "password.min_age_days": get("MinimumPasswordAge"),
        "password.history_size": get("PasswordHistorySize"),
        "password.complexity_enabled": None if complexity is None else complexity == 1,
        "password.reversible_encryption": None if reversible is None else reversible == 1,
        "lockout.threshold": get("LockoutBadCount"),
        "lockout.duration_minutes": get("LockoutDuration"),
        "account.guest_enabled": None if guest is None else guest == 1,
    }


def _ok(raw: dict[str, Any], name: str) -> dict[str, Any]:
    """Snippet output, or {} when the snippet failed (its facts become NOT_COLLECTED)."""
    part = raw.get(name)
    return part if isinstance(part, dict) and "_error" not in part else {}


# WHAT: Turn the PowerShell snippet output (windows_ps.py) into normalised facts.
def windows_facts(raw: dict[str, Any]) -> dict[str, Any]:
    facts: dict[str, Any] = {"os.family": "windows"}
    sec = _ok(raw, "secpol")
    if sec.get("inf"):
        facts.update(parse_secedit(sec["inf"]))

    profiles = _ok(raw, "firewall").get("profiles")
    if profiles:
        # WHY: one disabled profile (e.g. Public on shop Wi-Fi) is enough to fail.
        facts["firewall.enabled"] = all(bool(v) for v in profiles.values())

    av = _ok(raw, "defender")
    if av:
        facts["av.realtime_enabled"] = bool(av.get("realtime_enabled")) and bool(av.get("antivirus_enabled"))
        facts["av.signature_age_days"] = _int(av.get("signature_age_days"))

    sysv = _ok(raw, "system")
    if sysv:
        facts["service.smb1_enabled"] = sysv.get("smb1")
        rdp_off = _int(sysv.get("rdp_deny")) == 1
        # WHY: if RDP is switched off, NLA does not matter, so count it as safe.
        facts["rdp.nla_or_disabled"] = rdp_off or _int(sysv.get("rdp_nla")) == 1
        # REF: EnableLUA absent means the Windows default (UAC on).
        facts["uac.enabled"] = _int(sysv.get("uac_lua")) != 0
        # WHY: no InactivityTimeoutSecs value means "never lock", which must FAIL, so use 0.
        facts["session.lock_seconds"] = _int(sysv.get("inactivity_secs")) or 0
        # REF: 255 (0xFF) disables AutoRun on every drive type.
        facts["autorun.disabled_all"] = _int(sysv.get("autorun")) == 255
        facts["updates.automatic"] = _int(sysv.get("au_disabled")) != 1

    audit = _ok(raw, "audit")
    if audit:
        value = _int(audit.get("logon_value"))
        if value is None:  # older auditpol without "Setting Value": read the English text
            text = (audit.get("logon_inclusion") or "").lower()
            value = 3 if "success and failure" in text else 2 if "failure" in text else 1 if "success" in text else 0
        facts["audit.logon_success_failure"] = value == 3

    bl = _ok(raw, "bitlocker")
    if bl.get("protection"):
        facts["disk.encryption_on"] = bl["protection"].lower() == "on"

    patches = _ok(raw, "patches")
    if patches:
        facts["updates.days_since_last_patch"] = _int(patches.get("last_patch_days"))
        facts["os.name"] = patches.get("os_caption")
    return facts


# WHAT: Backwards-compatible: facts from a secedit .inf file (v0.1 CLI and tests).
def collect_windows_secedit(inf_path: str | Path) -> dict[str, Any]:
    """Collect facts from a `secedit /export /cfg file.inf` security policy export.

    On a Windows host the team runs (as Administrator):
        secedit /export /cfg C:\\temp\\secpol.inf /areas SECURITYPOLICY
    """
    return windows_facts(WindowsFileTarget(inf_path).collect_raw())


# WHAT: Facts from a Windows target (WinRM or a saved JSON/.inf file).
def collect_windows_target(target) -> dict[str, Any]:
    return windows_facts(target.collect_raw())


# WHAT: One entry point for any host: OS facts plus the services it runs.
def collect_host(platform: str, target, services: tuple[str, ...] = ()) -> dict[str, Any]:
    if platform == "windows":
        return collect_windows_target(target)
    facts = collect_linux_target(target)
    for svc in services:
        if svc in SERVICE_COLLECTORS:
            facts.update(SERVICE_COLLECTORS[svc](target))
    return facts


COLLECTORS = {
    "linux": collect_linux,
    "windows": collect_windows_secedit,
}
