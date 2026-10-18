# C300 Compliance Automation and Validation Platform: architecture and phase plan

Status: **draft v0.1 (8 Oct 2026)**, for team review before Week 1.
Supervisor: Zhong Weixian. Team leader: Ahmad.

## 1. Problem and goal

From the project brief: smaller organisations have no consistent way to know
whether their servers and workstations are still securely configured. Settings
are applied once at setup and then drift. The platform examines Linux and
Windows hosts for common misconfigurations (password and lockout policy, and
more), reports what fails, and shows how to fix it.

**MVP definition (what "done" means for the minimum product):**

1. Scan at least **2 Linux and 2 Windows lab VMs** that the team owns.
2. Check at least **25 controls** from one agreed standard, each traceable to that standard.
3. Produce a **report** (HTML or PDF) with pass/fail, evidence and remediation per control.
4. Keep **scan history** so a second scan shows what changed (drift).
5. **Validated:** every control's result matches a manual check on the lab VMs (accuracy table in the report).

Anything else (web dashboard, auto-remediation, scheduling, more OSes) is a stretch goal and only starts after the MVP is green.

## 2. Architecture

```
 Lab hosts                     Platform (Python, runs on a team laptop)
 ---------                     ----------------------------------------
 Linux VM  --SSH-->  +
                     |-->  Collectors  --facts-->  Rule engine  --results-->  Results store (SQLite)
 Windows VM --WinRM->+     (one per OS)               ^                         |            |
                                                      |                         v            v
                                          Control catalogue (YAML,          Drift diff    Reports
                                          mapped to chosen standard)                     (HTML/PDF)
```

| Component | Responsibility | Prototype today | MVP target |
|---|---|---|---|
| Collectors | Read settings from a host, output normalised facts | Linux files, Windows `secedit` export | Remote: SSH (Linux), WinRM/PowerShell (Windows) |
| Control catalogue | What to check, expected value, fix, reference | 12 CIS-style controls in YAML | 25+ controls mapped to the chosen standard |
| Rule engine | Compare facts to expectations | Done (7 operators) | Add regex, version compare if needed |
| Results store | Keep every scan | JSON file | SQLite (one file, no server) |
| Drift diff | What changed since last scan | Not built | Compare two scans per host |
| Reporting | Human and evidence output | Console + JSON | HTML (Jinja2), PDF optional |

**Key design decisions (also logged in the tracker):**

- **D-01 Agentless, read-only.** Nothing is installed on targets and nothing is changed. Easier to justify ethically and to deploy in small orgs.
- **D-02 Controls are data (YAML), not code.** Teammates can add controls without touching the engine.
- **D-03 Normalised facts.** Linux and Windows collectors output the same fact names, so one control serves both.
- **D-04 Missing data is never a pass.** `NOT_COLLECTED` is its own status.
- **D-05 Python 3.10+, stdlib + few libraries** (PyYAML, later paramiko or Fabric for SSH, pywinrm, Jinja2).

**Pushback for the team:** a web dashboard is tempting but it is the biggest
scope risk. The assessment rewards a working, validated scanner with good
evidence more than a pretty UI on an untested engine. Build the CLI and HTML
report first; add a dashboard only if Weeks 1 to 8 are on track.

## 3. Phases (12 weeks, plus buffer to January 2027)

Week numbers are project weeks. Fill in real dates once Week 1 is fixed.

| Phase | Weeks | Goal | Exit criteria (evidence) |
|---|---|---|---|
| 0. Set-up | 1 | Team, repo, roles, lab | Git repo with prototype, roles agreed, minutes W1, tracker shared |
| 1. Requirements and research | 2 to 3 | Pick the standard, select controls, design | Standard confirmed with supervisor, control list (25+) with references, architecture signed off |
| 2. Lab build | 2 to 4 (parallel) | Test targets exist | 2 Linux + 2 Windows VMs, one hardened and one weak of each, snapshots taken |
| 3. Core MVP | 4 to 7 | Remote collection + full catalogue | Scans run over SSH and WinRM, all controls implemented with unit tests |
| 4. Storage, drift, reporting | 7 to 9 | History and reports | SQLite history, drift diff, HTML report |
| 5. Validation | 9 to 10 | Prove results are right | Accuracy table: tool vs manual check for every control on every VM |
| 6. Hardening and stretch | 10 to 11 | Polish, optional extras | Error handling, docs, optional dashboard or scheduling |
| 7. Final report and demo | 11 to 12 | Submission | Report, poster/slides, demo video, final minutes |
| Buffer | after W12 to Jan 2027 | Absorb slippage, improvements | No new features after the code freeze date the team sets |

## 4. Team roles (3 members)

Team: **Ahmad** (team lead), **Ace**, **Jayen**. Every member writes code and owns at least one deliverable.
The Linux and Windows split below is a default; swap it if Ace or Jayen is stronger on the other OS.

| Member | Role | Owns | Backup for |
|---|---|---|---|
| Ahmad | Team lead / integrator | Plan, repo, minutes, tracker, rule engine, results store, drift, HTML report | Both collectors (reviews every PR) |
| Ace | Linux lead | Linux collector (SSH), Linux controls, Linux lab VMs | Windows collector |
| Jayen | Windows lead | Windows collector (WinRM/PowerShell), Windows controls, Windows lab VMs | Linux collector |
| All three | Validation | Manual checks vs tool results on every VM (Phase 5) | |

Each person reviews at least one other person's pull request every week, so nobody is the only one who understands a part of the code.

## 5. Ways of working

- **Git:** `main` is always runnable. Work on short branches (`feat/linux-ssh-collector`), open a pull request, one reviewer approves, tests pass, then merge.
- **Definition of done for a control:** YAML entry with standard reference, collector fact, unit test, checked manually on a lab VM.
- **Backups:** Git remote (GitHub) plus a weekly zip of docs to a shared drive. Lab VM snapshots before every change.
- **Weekly rhythm:** team meeting, minutes written the same day (template in `pm/minutes/`), tracker updated before the supervisor meeting.
- **Ethics:** scan only machines the team owns. No real organisation data in the repo.
- **Code comments and issue log:** every file follows `docs/02-coding-and-commenting-standard.md`. Every bug or mistake gets a row in the tracker's Issue log with root cause, fix and lesson, and the fixed code carries a matching `# FIX:` comment. The lessons are read out in the weekly meeting so the same mistake is not repeated.

## 6. Open questions for the supervisor (Week 1)

1. Which standard should controls map to? Team decision (D-06, 8 Oct 2026): use the generic CIS-style baseline for the prototype and early phases, then confirm with the supervisor.
2. Is a lab of local VMs acceptable as the validation environment?
3. What format are the 12 weekly minutes submitted in (Word, PDF, portal)?
4. Is a CLI plus HTML report acceptable, or is a web UI expected?
