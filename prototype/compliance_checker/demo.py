"""Demo playground: reset the sample hosts, then make deliberate drift.

Mirrors the supervisor's story (meeting 21 Oct): lock down a known baseline,
then change settings on purpose and show the scanner catching the drift.
Works only on the COPY in data/demo-targets, never on samples/ or a real host.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

PROTOTYPE = Path(__file__).resolve().parent.parent
SAMPLES = PROTOTYPE / "samples" / "playground"
WORK = PROTOTYPE / "data" / "demo-targets"
DEMO_INVENTORY = PROTOTYPE / "inventory" / "demo.yaml"


# WHAT: Fresh copy of the pristine demo hosts (the "baseline" state).
def reset() -> Path:
    if WORK.exists():
        shutil.rmtree(WORK)
    shutil.copytree(SAMPLES, WORK, ignore=shutil.ignore_patterns("README.md"))
    return WORK


def ensure() -> Path:
    if not WORK.exists():
        reset()
    return WORK


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace(old, new, 1) if old else text + new, encoding="utf-8")


# WHAT: Simulate what goes wrong in a small shop between two weekly scans.
# Each line says who "did" it, so the drift is easy to explain in a demo.
DRIFT_STORY = [
    "SHOP-WEB-01: a contractor re-enabled root SSH login to debug the site",
    "SHOP-WEB-01: someone turned on directory listing to share product images",
    "SHOP-WEB-01: the firewall was switched off while testing a payment plugin",
    "SHOP-DB-01: the database was opened to all interfaces for a reporting tool",
    "POS-WIN11-01: real-time antivirus was turned off because it 'slowed the till'",
    "POS-WIN11-01: SMBv1 was turned on to reach an old receipt printer share",
    "POS-WIN11-01: the Public firewall profile was turned off",
]


def drift() -> list[str]:
    ensure()
    web, db = WORK / "shop-web-01", WORK / "shop-db-01"
    _edit(web / "etc/ssh/sshd_config", "PermitRootLogin no", "PermitRootLogin yes")
    _edit(web / "etc/nginx/sites-enabled/freshcart", "\tlocation / {",
          "\tlocation /images/ { autoindex on; }\n\tlocation / {")
    _edit(web / "etc/ufw/ufw.conf", "ENABLED=yes", "ENABLED=no")
    _edit(db / "etc/mysql/mariadb.conf.d/50-server.cnf", "10.10.20.11", "0.0.0.0")
    pos_path = WORK / "pos-win11-01.json"
    pos = json.loads(pos_path.read_text(encoding="utf-8"))
    pos["defender"]["realtime_enabled"] = False
    pos["system"]["smb1"] = True
    pos["firewall"]["profiles"]["Public"] = False
    pos_path.write_text(json.dumps(pos, indent=2), encoding="utf-8")
    return DRIFT_STORY
