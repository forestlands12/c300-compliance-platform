"""Collectors read raw OS configuration and turn it into normalised facts.

Every collector returns a flat dict of the SAME fact names (e.g.
"password.min_length") whatever the OS, so one control can cover Linux and
Windows. Adding a new OS means adding a collector, not rewriting controls.

Collectors are read-only: they never change the target.
"""
from __future__ import annotations

import configparser
import os
import stat
from pathlib import Path
from typing import Any

# ASSUMPTION: these match current OpenSSH; older versions may differ. REF: man sshd_config
# OpenSSH defaults used when a directive is absent from sshd_config
# (see `man sshd_config`). Recorded so the report shows the effective value.
SSHD_DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "maxauthtries": "6",
}


# WHAT: Generic parser for Linux config files ('KEY value' or 'key = value').
def _read_kv(path: Path, sep: str | None = None) -> dict[str, str]:
    """Parse simple 'KEY value' or 'key = value' files, ignoring comments."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
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


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


# WHAT: Turn Linux config files into normalised facts (password, lockout, SSH, file permissions).
# SECURITY: read-only. Never write to the target (REQ-07).
# TODO(Ace, T-09): read the same files over SSH from lab VMs instead of a local path.
# TODO(Ace, T-11): check pam_faillock is actually enabled in /etc/pam.d, not only configured.
def collect_linux(root: str | Path = "/") -> dict[str, Any]:
    """Collect facts from a Linux filesystem rooted at `root`.

    root="/" scans the live machine; a folder path scans a saved snapshot
    (used for the samples and for tests).
    """
    root = Path(root)
    facts: dict[str, Any] = {"os.family": "linux"}

    login_defs = _read_kv(root / "etc/login.defs")
    facts["password.max_age_days"] = _int(login_defs.get("pass_max_days"))
    facts["password.min_age_days"] = _int(login_defs.get("pass_min_days"))
    facts["password.min_length"] = _int(login_defs.get("pass_min_len"))

    # WHY: pam_pwquality overrides login.defs for minimum length on modern distros.
    pwquality = _read_kv(root / "etc/security/pwquality.conf", sep="=")
    if "minlen" in pwquality:
        facts["password.min_length"] = _int(pwquality["minlen"])

    faillock = _read_kv(root / "etc/security/faillock.conf", sep="=")
    facts["lockout.threshold"] = _int(faillock.get("deny"))
    unlock = _int(faillock.get("unlock_time"))
    # WHY: unlock_time is in seconds; 0 means "admin must unlock", which is stricter, so treat it as very long.
    facts["lockout.duration_minutes"] = None if unlock is None else (
        10**6 if unlock == 0 else unlock // 60)

    sshd_path = root / "etc/ssh/sshd_config"
    if sshd_path.is_file():
        sshd = {**SSHD_DEFAULTS, **_read_kv(sshd_path)}
        facts["ssh.permit_root_login"] = sshd["permitrootlogin"].lower()
        facts["ssh.password_authentication"] = sshd["passwordauthentication"].lower()
        facts["ssh.max_auth_tries"] = _int(sshd["maxauthtries"])

    shadow = root / "etc/shadow"
    if shadow.exists():
        facts["file.etc_shadow.mode"] = format(stat.S_IMODE(os.stat(shadow).st_mode), "04o")

    return facts


# WHAT: Turn a Windows security policy export (secedit .inf) into the same normalised facts.
# TODO(Jayen, T-10): collect over WinRM/PowerShell from lab VMs instead of an exported file.
def collect_windows_secedit(inf_path: str | Path) -> dict[str, Any]:
    """Collect facts from a `secedit /export /cfg file.inf` security policy export.

    On a Windows host the team runs (as Administrator):
        secedit /export /cfg C:\\temp\\secpol.inf /areas SECURITYPOLICY
    """
    raw = Path(inf_path).read_bytes()
    # WHY: secedit writes UTF-16 LE with a BOM; hand-made samples may be UTF-8. Reading as UTF-8 only would crash on real exports.
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig")

    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str  # keep key case
    parser.read_string(text)
    sa = parser["System Access"] if parser.has_section("System Access") else {}

    def get(key: str) -> int | None:
        return _int(sa.get(key, "").strip()) if key in sa else None

    complexity = get("PasswordComplexity")
    reversible = get("ClearTextPassword")
    return {
        "os.family": "windows",
        "password.min_length": get("MinimumPasswordLength"),
        "password.max_age_days": get("MaximumPasswordAge"),
        "password.min_age_days": get("MinimumPasswordAge"),
        "password.history_size": get("PasswordHistorySize"),
        "password.complexity_enabled": None if complexity is None else complexity == 1,
        "password.reversible_encryption": None if reversible is None else reversible == 1,
        "lockout.threshold": get("LockoutBadCount"),
        "lockout.duration_minutes": get("LockoutDuration"),
        "account.guest_enabled": None if get("EnableGuestAccount") is None
        else get("EnableGuestAccount") == 1,
    }


COLLECTORS = {
    "linux": collect_linux,
    "windows": collect_windows_secedit,
}
