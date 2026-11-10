# Prototype: compliance checker (v0.2, one-click scan and dashboard)

A read-only scanner for a small company's machines. It collects security
settings, checks them against a YAML baseline (35 checks for Windows 11, Linux,
nginx and MySQL/MariaDB), keeps every scan in a history file, shows **drift**
since each machine's baseline, and puts it all on a local web dashboard with a
one-click **Run scan** button. An optional AI assistant explains failed checks
in plain English.

The scenario is "SME Supermarket": an online shop web server, a customer
database, a cashier PC and a back-office PC (supervisor meeting, 21 Oct 2026:
one company story, baseline then deliberate drift, scheduled scans, no live
monitoring).

## Quick start (demo, no VMs needed)

Needs Python 3.10+. From this `prototype` folder:

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows   (Linux/macOS: source .venv/bin/activate)
python -m pip install -r requirements.txt

python -m compliance_checker demo reset      # fresh copy of the 4 sample machines
python -m compliance_checker dashboard       # open http://127.0.0.1:8300 and press Run scan
```

Then show drift, the way the supervisor described it:

```bash
python -m compliance_checker demo drift      # deliberately weaken settings on the sample machines
```

Press **Run scan** again: the score drops, and *Configuration drift* lists every
change (for example "Host firewall is enabled: true → false, worse").
Click a failing check, or a host, then **Explain this** for a plain-English explanation.

## Commands

| Command | What it does |
|---|---|
| `dashboard` | Local web dashboard on http://127.0.0.1:8300 (this PC only) |
| `scan-all [--trigger scheduled]` | Scan every host in the inventory and save the run (for Task Scheduler / cron) |
| `baseline [--host NAME]` | Make each host's latest scan its baseline (first scan does this automatically) |
| `demo reset` / `demo drift` | Reset the sample machines / apply deliberate drift |
| `scan --platform linux\|windows --source PATH` | v0.1 single-host scan, prints a table |
| `export-windows-script` | Writes `collect_windows.ps1` for collecting from a Windows PC with no network access |
| `ai-test` | Checks the AI assistant settings and connection |
| `script-check` | Checks `scripts/fyp-scan.sh` against `controls/cis-ubuntu-24.04.yaml`, so the script and its risk ratings never drift apart |

Add `--inventory inventory/playground.yaml` to `dashboard`, `scan-all` and
`baseline` to use real VMs instead of the demo. Exit codes of `scan-all`:
`0` no failures, `1` at least one failed check.

## Two ways a machine is checked

| `scanner:` in the inventory | What runs | Rules |
|---|---|---|
| `builtin` (default) | our Python collectors | `controls/baseline.yaml` (35 generic CIS-style checks) |
| `script` | a shell scanner **on the machine**, read-only | its own catalogue, e.g. `controls/cis-ubuntu-24.04.yaml` |

For Ubuntu the team uses the second one: `scripts/fyp-scan.sh` (Ace) checks the 42
CIS Ubuntu 24.04 v1.0.0 rules the team kept, using the audit method from the CIS
PDF. The platform copies it to the VM, runs it, and turns each line into a normal
result, so the rules are never written twice and cannot disagree. The risk rating
(likelihood x impact), the business reason and the ISO 27001 draft mapping come
from the catalogue, which was generated from the team's selection log.

`scripts/harden.sh` fixes the same rules, but the platform never runs it: a
scanner only reads (REQ-07). The report names the step of `harden.sh` that fixes
each failure, and a person runs it on the machine.

See `inventory/ubuntu-script.example.yaml` for the settings and the one-time
sudo set-up inside the VM.

## Weekly scheduled scan

Windows (run once in an Administrator prompt, adjust the path):

```bat
schtasks /create /tn "C300 weekly scan" /sc weekly /d MON /st 08:00 ^
  /tr "cmd /c cd /d C:\path\to\prototype && .venv\Scripts\python -m compliance_checker scan-all --inventory inventory\playground.yaml --trigger scheduled"
```

Linux (crontab -e):

```
0 8 * * 1 cd /path/to/prototype && .venv/bin/python -m compliance_checker scan-all --inventory inventory/playground.yaml --trigger scheduled
```

Scheduled runs show as blue dots on the dashboard's score chart.

## Real VMs

Copy `inventory/playground.example.yaml` to `inventory/playground.yaml` and fill
in the VM addresses. Linux VMs are reached over SSH (`pip install paramiko`),
Windows 11 VMs over WinRM (`pip install pywinrm`). Passwords are never stored in
the file: `password_env` names an environment variable, and an SSH key is better
still. Every command the scanner runs is read-only and comes from this code, not
from the inventory.

## Optional AI assistant

The **Explain this** buttons always work. With no settings they use a built-in
explanation made from the baseline's own rationale and fix (no network needed,
so the demo never depends on wifi). To use a real model, such as the school's
AI account, set these in the terminal before starting the dashboard:

```powershell
$env:CC_AI_BASE_URL = "https://<address the school gives you>/v1"
$env:CC_AI_MODEL    = "<model name>"
$env:CC_AI_API_KEY  = Read-Host "API key"      # never save the key in a file in this repo
python -m compliance_checker ai-test            # run on school wifi or the VPN
python -m compliance_checker dashboard
```

The header chip shows `AI: <model>` when a model is set, or `AI: offline`.
The assistant speaks the OpenAI-compatible `/chat/completions` format, which
most self-hosted and enterprise gateways (vLLM, Ollama, LiteLLM) support.
**Not yet confirmed** that the school's account uses this format: check with
the module chair (T-20 in the tracker).

What is sent: the check's id, title, severity, rule and found value, plus the
platform and the machine's role. Host names are never sent and private IP
addresses are masked. If the model is slow or unreachable, the built-in
explanation is shown instead and the page says why.

## How it fits together

```
inventory/*.yaml ─► inventory.py ─► targets.py (snapshot / file / SSH / WinRM)
                                        │
controls/baseline.yaml ─► loader.py     ▼
            │                     collectors.py (normalised facts)
            └──────────► checks.py (rule engine) ◄──┘
                              │
                engine.py (scan every host in parallel) ─► store.py (SQLite history)
                                                               │
                                     scoring.py (score, drift, frameworks)
                                        │                       │
                                 web/ (dashboard)         cli.py scan-all
                                        │
                                 assistant.py (optional AI explanations)
```

- **Controls are data.** Adding a check usually means adding YAML, not Python.
- **Missing data is never a pass.** A setting that could not be read is `NOT_COLLECTED`,
  left out of the score and listed under *Could not check* (decision D-04).
- **Every number on the dashboard comes from `scoring.py`**, so the dashboard and
  the exported evidence (`Export evidence`, JSON) cannot disagree.
- **The dashboard listens on this PC only** (127.0.0.1) and every POST needs a
  per-start random token, so other web pages cannot start scans (CSRF).

## Tests

```bash
python -m unittest discover -s tests -v
```

25 tests: rule engine, collectors, scan of all four demo machines, deliberate
drift caught, fixed drift shown as better, unreachable host reported as an
error, scoring, dashboard API (token required, one-click scan, baseline,
evidence) and the AI assistant against a fake AI server (offline fallback,
caching, no host names or private IPs sent). The dashboard tests are skipped if
Flask is not installed.

## Known limitations

- Windows WinRM collection and Linux SSH collection are written but **not yet
  run against the real VMs** (T-09, T-10). The demo uses saved snapshots.
- Framework mapping (CIS Controls v8, PCI DSS v4.0) is indicative, not yet
  checked against the official documents (T-05).
- Thresholds are CIS-style; the exact CIS Benchmark version is still to be fixed.
- The AI assistant is tested only against a fake server; the school account has
  not been tried yet.
