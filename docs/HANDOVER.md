# Handover checkpoint

## Session 1: 8 Oct 2026 (pre-project head start)

**State:** Phase 0 (set-up) materials drafted. Project has not officially started.
Nothing is in Git yet; files live only in the project's shared folder. **Not backed up anywhere else yet.**

### Done and verified

- Architecture and phase plan drafted: `docs/01-architecture-and-phase-plan.md`.
- Tracker created and reopened successfully: `pm/FYP_Tracker.xlsx` (17 tasks, 8 risks, 6 decisions, 10 requirements, 1 bug, 2 evidence rows, 12-week minutes log).
- Minutes: `pm/minutes/TEMPLATE.md`, `week-01.md` to `week-12.md`, `Minutes_Template.docx`.
- Prototype v0.1.0 in `prototype/`:
  - 10 unit tests pass (`python -m unittest discover -s tests -v`, Python 3.13).
  - Scanned 3 targets; real output saved in `prototype/evidence/first-run-output.txt`:
    - `linux-web-01` sample: 1 pass, 6 fail, 1 not collected.
    - `win-ws-01` sample: 6 pass, 2 fail, 1 not collected.
    - Live Linux build container: 1 pass, 2 fail, 5 not collected.
  - One bug found by the tests and fixed (B-01 in tracker).

### Not done / not verified

- Prototype not tested on Windows itself or on a real Windows `secedit` export (sample is hand-written in the same format; UTF-16 decoding is unit tested).
- Prototype not tested with Python 3.10 to 3.12.
- No Git repo, no backup.
- Roles, team size and target standard are assumptions.

### Next steps (in order)

1. Create the team GitHub repo and push `fyp-starter/` (T-01). This is also the first backup.
2. Each teammate runs the prototype and tests (T-03), including one person on Windows with a real `secedit` export.
3. Week 1 meeting: agree roles (T-02), fill `week-01.md`.
4. Ask the supervisor the 4 questions in plan section 6, especially the standard (T-04).

### Open questions for Ahmad

- Which compliance standard does the supervisor expect?
- How many teammates, and their names, so owners can be filled in?

## Session 2: 8 Oct 2026 (team and standards)

**Inputs from Ahmad:** team is Ahmad, Ace, Jayen. Use the generic CIS-style baseline for now (D-06 accepted).
Wants tagged code comments explaining what code does and how issues were resolved, and this written into planning.

### Done and verified

- Plan section 4 now has 3-person roles (default: Ace Linux, Jayen Windows, Ahmad lead/engine/reporting).
- New `docs/02-coding-and-commenting-standard.md`: comment tags and a 7-step issue process (D-07).
- Prototype code tagged with `# WHAT/WHY/FIX/TODO/SECURITY/ASSUMPTION`; B-01 fix comment in `controls/baseline.yaml`. 10 unit tests still pass after the edit.
- Tracker v0.2: owners filled, Bugs sheet replaced by an Issue log with Root cause, How resolved, Lesson columns; D-07 and D-08 added; T-18, T-19 added.
- Minutes templates (Markdown and Word) gained a section "Issues and lessons".

### Still open

- Ace and Jayen to confirm the Linux/Windows split (T-19).
- No Git repo or backup yet (T-01).

## Session 3: 18 Oct 2026 (Git repo, T-01)

### Done and verified

- `fyp-starter/` is now a Git repository on branch `main` with one initial commit (in the project's shared folder only).
- `.gitignore` extended for VM images and ISOs, Python caches, `.env`, Office and LibreOffice lock files, OS clutter. `prototype/evidence/` stays tracked because it is submission evidence; `reports/` stays ignored because live scans may hold sensitive details.
- `.gitattributes` added so Windows and Linux machines store text the same way (LF), and Office files are treated as binary.
- 10 unit tests still pass before the commit.
- A single-file copy of the repo, `fyp-starter.bundle`, sits next to this folder for moving it onto GitHub.

### Not done

- No GitHub remote yet: Ahmad creates the private repo and pushes (steps below). Until then there is still **no backup outside the project folder**.

## Session 4: 28 to 29 Oct 2026 (one-click scan, dashboard, AI assistant)

Branch: `feat/one-click-scan-dashboard` (not merged to `main` yet; `main` is tagged `v0.1.0`).

### Done and verified

- Scan engine for many hosts (`engine.py`), inventory file (`inventory/`), SQLite history (`store.py`),
  score, drift and framework view (`scoring.py`), 35 checks for Windows 11, Linux, nginx and MySQL/MariaDB.
- Demo playground "SME Supermarket": 4 sample machines, `demo reset` and `demo drift`
  (the supervisor's "baseline, then deliberate drift" story). Verified: score 80.3% at baseline,
  69.1% after drift, every drifted host listed as "worse".
- Dashboard tested in headless Chrome at desktop and phone width: Run scan, progress, host panel,
  set baseline, failing-check details, export evidence. Two UI bugs found and fixed (B-04, B-05).
- Optional AI assistant (`assistant.py`): "Explain this" on every failed check. Offline built-in
  explanation by default; a real model is used only when `CC_AI_BASE_URL` and `CC_AI_MODEL` are set.
  Host names are never sent, private IPs are masked, the key is read from the environment.
  `python -m compliance_checker ai-test` checks the connection. Tested against a fake
  OpenAI-compatible server, in unit tests and in the browser.
- Tests: 25 pass (`python -m unittest discover -s tests -v`), 15 of them new.
- `requirements.txt` now lists Flask (the dashboard needs it).
- Tracker: B-02 to B-05 in the Issue log, T-20 and T-21, R-09 and R-10, D-09 (proposed).

### Not done / not verified

- Not run against real VMs: SSH and WinRM collection are written but untested (T-09, T-10).
- The school AI account has not been tried. Its API format is assumed to be
  OpenAI-compatible; confirm with the module chair (T-20).
- Scheduled scan commands are documented in `prototype/README.md` but not yet set up on the desktop.
- Not pushed to GitHub (no remote yet). The bundle `fyp-starter.bundle` holds both branches.

### Next steps (in order)

1. Ahmad: run the demo on the laptop (README quick start) and decide whether to merge the branch into `main`.
2. Ace and Jayen: point `inventory/playground.yaml` at the real VMs and run `scan-all` (T-09, T-10).
3. Ahmad: email the module chair about the AI account (T-20), then run `ai-test` on school wifi.
4. Set up the weekly scheduled scan on the desktop.

## Working on two machines (desktop and laptop)

Git is the bridge. GitHub holds the one true copy; each machine is a clone.

**First-time setup (once)**

1. On github.com, create a new **private** repository, for example `c300-compliance-platform`. Do not add a README, .gitignore or licence (the repo already has them).
2. Download `fyp-starter.bundle` from the project files onto the desktop, then in a terminal in the same folder:

   ```bash
   git clone fyp-starter.bundle c300-compliance-platform
   cd c300-compliance-platform
   git remote set-url origin https://github.com/forestlands12/c300-compliance-platform.git
   git push -u origin main
   ```
3. On the laptop: `git clone https://github.com/forestlands12/c300-compliance-platform.git`
4. On GitHub, Settings, Collaborators: invite Ace and Jayen. They clone the same way.
5. On each machine, set your name once: `git config --global user.name "Ahmad"` and `git config --global user.email "<your GitHub email or noreply address>"`.

**What runs where**

| Work | Laptop | Desktop |
|---|---|---|
| Writing rules, code, docs, minutes | Yes | Yes |
| Unit tests (use the sample files, no VM needed) | Yes | Yes |
| Real scans against Ubuntu and Windows VMs | Optional: small Ubuntu Server VM only (~15 GB) | Yes, main place |
| VM images and ISOs | Never in Git | Never in Git |

**Every session, on either machine**

```bash
git pull                     # start: get what the other machine pushed
# ... work, run: python -m unittest discover -s tests -v   (from prototype/)
git add -A
git commit -m "Short description of what changed"
git push                     # end: so the other machine and the team see it
```

Rules that keep this painless:

1. Always pull before you start and push before you stop. Forgetting is the main cause of merge conflicts.
2. Never edit `pm/FYP_Tracker.xlsx` or a `.docx` on both machines without pushing in between. Git cannot merge Office files; if both change, you have to pick one and redo the other's edits by hand.
3. Real scan output you want as evidence goes in `prototype/evidence/` (JSON plus screenshots) and gets committed from the desktop. Throwaway runs go in `reports/`, which Git ignores.
4. Small, frequent commits. A commit message says what changed and, for a fix, the bug id (for example `Fix B-02: ...`).
5. Larger features go on a branch (`git switch -c feature/linux-ssh-checks`) and merge to `main` once tests pass, so `main` always runs.

**Reaching the desktop's VMs from the laptop (optional)**

If the desktop stays on at home, install Tailscale on both machines and use SSH (Ubuntu VM) or Remote Desktop (Windows VM) over it. This avoids opening ports on the home router. Set this up only if you actually need it.

**Backups:** GitHub is backup number one. Keep a second, independent copy (for example a monthly zip of the repo on OneDrive or a USB drive), because a deleted repo or a bad force-push would otherwise lose everything.
