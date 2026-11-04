# scripts/

Shell scripts that run **on an Ubuntu machine**, not on the scanning PC.

| File | What it does | Author |
|---|---|---|
| `fyp-scan.sh` | Checks the 42 CIS Ubuntu 24.04 v1.0.0 rules the team kept and prints one line per rule. Read-only. | Ace |
| `harden.sh` | Applies those rules (remediation). Backs up every file it touches and writes `rollback.sh`. | Ace |

Both are kept here **unchanged**, so there is one version of each in the team.
If Ace changes one, replace the file here and say so in the commit message.

## How the platform uses them

`fyp-scan.sh` is the Ubuntu scanner. The Python tool copies it to the VM, runs it
over SSH, and reads its output; see `compliance_checker/script_scan.py`. The risk
rating, the business reason and the ISO mapping of each rule come from
`controls/cis-ubuntu-24.04.yaml`, generated from the team's selection log.

`harden.sh` is **never** run by the platform. A scanner must only read
(REQ-07), and changing a machine is a decision a person makes. The dashboard
points at it as the fix, and you run it yourself on the VM:

```bash
sudo ./harden.sh --dry-run    # show every change, change nothing
sudo ./harden.sh              # apply, then reboot and scan again
sudo ~/fyp-evidence/harden-<timestamp>/rollback.sh   # undo
```

## Output format of fyp-scan.sh

One line per rule, fields separated by `|`:

```
host|CIS-5.1.20|SSH root login disabled|no|yes|FAIL|2026-11-04T14:32:00+08:00
```

and a final score line:

```
host|SCORE|Compliance score|42 rules|15 passed|35%|2026-11-04T14:32:00+08:00
```

The parser in `script_scan.py` accepts any line in that shape, so a new rule
added to the script shows up as soon as it is added to the YAML catalogue too.
A rule in the script but not in the catalogue is still reported (with its own
title and a medium severity), and `python -m compliance_checker script-check`
lists any mismatch between the two.
