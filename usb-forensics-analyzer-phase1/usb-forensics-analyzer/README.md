# USB Forensics Analyzer — Artifact Labs

Automated Windows USB evidence correlation with explainable, confidence-scored
findings, conflict/anti-forensics flagging, and ground-truth validation.

## Layout
- `usbfa/schema.py` — the ONE shared record format. All parsers emit `EvidenceRecord`.
- `usbfa/parsers/` — (Phase 2) registry, setupapi, event-log parsers
- `scripts/collect.ps1` — evidence collection, run inside lab VMs only
- `docs/phase1-lab-setup.md` — VM + logging + snapshot checklist
- `docs/scenarios.md` — ground-truth test scenarios S01–S10
- `evaluation/ground_truth/` — one CSV per scenario (answer key)
- `evaluation/gap_check.csv` — existing tools vs ground truth
- `evidence/` — collected evidence (git-ignored except manifests)

## Setup
    python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
    pip install -r requirements.txt
    python -m usbfa.schema    # smoke test
