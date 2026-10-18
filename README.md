# C300 Compliance Automation and Validation Platform: team starter

Head start for the FYP team, created 8 Oct 2026 before the project officially begins.
Everything here is a **draft for the team to challenge**, not a final decision.

## Start here (in this order)

1. `docs/01-architecture-and-phase-plan.md`: what we are building, the MVP, phases, roles (Ahmad, Ace, Jayen).
1. `docs/02-coding-and-commenting-standard.md`: comment tags (`# WHAT`, `# WHY`, `# FIX`, `# TODO`) and how to log every issue and its fix.
2. `prototype/`: run it yourself (see `prototype/README.md`), takes 2 minutes.
3. `pm/FYP_Tracker.xlsx`: tasks, risks, decisions, requirements, bugs, evidence, minutes log.
4. `pm/minutes/`: weekly minutes (Markdown per week, plus a Word template).
5. `docs/HANDOVER.md`: where things stand and what to do next.

## Folder layout

```
fyp-starter/
├── README.md
├── docs/
│   ├── 01-architecture-and-phase-plan.md
│   ├── 02-coding-and-commenting-standard.md
│   └── HANDOVER.md
├── pm/
│   ├── FYP_Tracker.xlsx
│   └── minutes/  (TEMPLATE.md, week-01.md ... week-12.md, Minutes_Template.docx)
└── prototype/
    ├── compliance_checker/   (Python package)
    ├── controls/baseline.yaml
    ├── samples/              (fake Linux and Windows targets)
    ├── tests/
    └── evidence/             (first real run output)
```

## Getting the repo

This folder is already a Git repo. To put it on GitHub and clone it onto the laptop and desktop,
follow "Working on two machines" in `docs/HANDOVER.md`.
