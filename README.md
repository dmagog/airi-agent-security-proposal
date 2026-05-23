# Goal-Consistent Action Verification for Tool-Using LLM Agents

Supplementary materials for the AIRI Summer School 2026 research proposal by Georgy Mamarin.

## Contents

- `README_proposal.md` — proposal text.
- `experiments/gctg_offline.py` — offline rules-only GCAV prototype for the ASB `system_admin_agent` subset.
- `experiments/results/gctg_offline_summary.md` — generated result summary.

## Source Paper

**Agent Security Bench (ASB): Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents**, ICLR 2025, CORE A*.

- Paper: https://proceedings.iclr.cc/paper_files/paper/2025/hash/5750f91d8fb9d5c02bd8ad2c3b44456b-Abstract-Conference.html
- ASB code/data: https://github.com/agiresearch/ASB

## Reproducing the Offline Prototype

Clone ASB separately and run:

```bash
python3 experiments/gctg_offline.py --asb-repo /path/to/ASB
```

The script expects ASB JSONL files under `/path/to/ASB/data`.

## Scope

This is a minimal offline sanity check, not a full ASB reproduction. The prototype evaluates tool-level consistency because ASB simulated tools do not include arguments.
