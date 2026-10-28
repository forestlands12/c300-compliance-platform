# Playground demo snapshots (fake data)

A pretend SME supermarket with an online shop. Nothing here comes from a real machine.
These let anyone run the scanner and dashboard without VMs (`inventory/demo.yaml`).

| Host | Role | What is deliberately weak at baseline |
|---|---|---|
| `shop-web-01/` | Ubuntu 24.04, nginx online shop | cloud-init file turns SSH password login back on; auditd off; no HSTS |
| `shop-db-01/` | Ubuntu 24.04, MariaDB (customers, orders, stock) | weak password ageing; faillock configured but not in PAM; DB connections not forced to TLS |
| `pos-win11-01.json` | Windows 11 cashier PC | BitLocker off, AutoRun not fully disabled |
| `office-win11-01.json` | Windows 11 back-office PC | weak password and lockout policy, no screen lock, stale patches, BitLocker unreadable (no vTPM) |

Linux snapshots are folders laid out like `/`. `_commands/*.txt` holds the output of
read-only commands (e.g. `systemctl is-active auditd`), `_modes.txt` holds file permissions
(Git does not keep them). Windows files have the same shape as `collect_windows.ps1` output.

`python -m compliance_checker demo reset` copies these into `data/demo-targets/`,
and `demo drift` then makes deliberate changes there (the supervisor's
"baseline, then drift" story), so these originals never change.
