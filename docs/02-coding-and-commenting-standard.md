# Coding, commenting and issue-log standard

Applies to every file in the repo. Agreed: 8 Oct 2026 (decision D-07). Owner: Ahmad.

The goal: anyone on the team (or the examiner) can open a file and understand
**what** the code does, **why** it was done that way, and **what went wrong before and how it was fixed**.

## 1. Comment tags

In Python, YAML and PowerShell, `#` starts a comment. We use a small, fixed set
of tags after the `#` so comments can be searched.

| Tag | Use it for | Example |
|---|---|---|
| `# WHAT:` | One line above a function or block saying what it does in plain English | `# WHAT: Read login.defs and turn it into password facts.` |
| `# WHY:` | A non-obvious choice, so nobody "simplifies" it back into a bug | `# WHY: sshd uses the FIRST occurrence of a setting, so keep the first one.` |
| `# FIX(B-xx):` | Code that was changed to fix a logged bug. Says what broke and how it was resolved | see section 3 |
| `# ASSUMPTION:` | Something we assume about the target that could be wrong | `# ASSUMPTION: OpenSSH default MaxAuthTries is 6 when unset.` |
| `# SECURITY:` | Anything about credentials, permissions or the read-only rule | `# SECURITY: never log the SSH password.` |
| `# TODO(name, T-xx):` | Planned work, with an owner and tracker task | `# TODO(Ace, T-09): collect over SSH instead of local files.` |
| `# REF:` | Where a value or rule comes from (standard, man page, docs) | `# REF: man sshd_config` |

**Rules**

- Comment the *why*, not every line. `x = x + 1  # add 1` is noise.
- Every function has a `# WHAT:` line or a docstring.
- A `# TODO` without a name and task ID is not allowed in a pull request.
- Never delete a `# FIX(B-xx):` comment unless that code itself is removed.

**Find things fast**

```bash
grep -rn "# FIX"   .     # every bug fix and how it was resolved
grep -rn "# TODO"  .     # outstanding work and who owns it
grep -rn "# SECURITY" .  # security-sensitive spots to re-check before submission
```

## 2. Issue log: how to handle a bug or mistake

Do these steps in order for every bug, wrong result, broken build or process mistake
(for example, "pushed straight to main", "lost a VM snapshot").

1. **Log it** in `pm/FYP_Tracker.xlsx` > *Issue log*: new ID `B-xx`, what happened, how to reproduce.
2. **Find the root cause**, not just the symptom. Write it in the *Root cause* column.
3. **Write a test that fails** because of the bug (for code bugs).
4. **Fix it** and add a `# FIX(B-xx):` comment at the changed code.
5. **Commit** with the ID in the message: `fix(B-xx): short description`.
6. **Fill in *How resolved* and *Lesson / prevention*** in the Issue log.
7. **Read the lesson out** in the next weekly meeting; it goes in the minutes under "Issues and lessons".

## 3. Example from the prototype (real, B-01)

What happened: on the first test run, the control catalogue failed to load with
`yaml.scanner.ScannerError: mapping values are not allowed here`.

In `prototype/controls/baseline.yaml`:

```yaml
    remediation:
      # FIX(B-01, 8 Oct 2026, Ahmad): YAML failed to load because the text
      # contained "Accounts: Guest..." and an unquoted colon starts a new key.
      # Resolved by quoting the whole value. Lesson: quote any text with ":".
      windows: "Set 'Accounts: Guest account status' to Disabled."
```

Tracker Issue log row: *Root cause* "unquoted colon inside a YAML value";
*Lesson / prevention* "quote remediation text; the loader test catches it".

## 4. Other coding rules

- Python 3.10+, PEP 8 style, 4-space indent, names in `snake_case`.
- `main` must always run and pass tests. Work on a branch, open a pull request, one teammate reviews.
- Never commit passwords, keys, real hostnames or real scan output. Use `.gitignore`.
- Before changing someone else's module, tell them (or tag them on the PR).
- Run `python -m unittest discover -s tests -v` before every push.
