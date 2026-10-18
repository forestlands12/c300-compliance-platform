# Prototype: compliance checker (v0.1.0)

A read-only command line tool that collects security settings from a host,
checks them against a YAML control catalogue, and prints a pass/fail report
with fixes. This is a **throwaway-quality spike** to prove the idea, not the MVP.

## Run it

Needs Python 3.10+.

```bash
cd prototype
python -m pip install -r requirements.txt

# Sample targets (fake data, works on any OS)
python -m compliance_checker scan --platform linux   --source samples/linux-web-01
python -m compliance_checker scan --platform windows --source samples/win-ws-01/secpol.inf --json-out report.json

# Your own Linux machine or VM (read-only; some files need sudo to read)
sudo python3 -m compliance_checker scan --platform linux --source /

# Your own Windows machine: export the policy first (Administrator prompt)
secedit /export /cfg C:\temp\secpol.inf /areas SECURITYPOLICY
python -m compliance_checker scan --platform windows --source C:\temp\secpol.inf

# Tests
python -m unittest discover -s tests -v
```

Exit codes: `0` all pass, `1` at least one FAIL, `2` no fails but some controls could not be checked.

## How it fits together

```
controls/baseline.yaml ──► loader.py ──┐
                                       ├──► checks.py (rule engine) ──► report.py (console + JSON)
target ──► collectors.py (facts) ──────┘
```

- **collectors.py** reads raw config and outputs *normalised facts* such as
  `password.min_length`. Linux and Windows produce the same fact names, so one
  control can cover both.
- **controls/baseline.yaml** is data, not code. Adding a check usually means
  adding YAML, not Python.
- **checks.py** compares fact vs expected. A missing fact is `NOT_COLLECTED`,
  never a silent pass.
- **report.py** prints the table and writes JSON evidence (for the report/appendix).

## Known limitations (deliberate, for later phases)

- Linux lockout is read from `faillock.conf` only; it does not check that
  `pam_faillock` is actually enabled in the PAM stack.
- Windows uses a `secedit` export file, not a live remote query (WinRM/PowerShell).
- One host per run, no database, no web dashboard, no drift history.
- Thresholds are CIS-style placeholders, not yet mapped to an official benchmark.

The first real run output is in `evidence/first-run-output.txt`.
