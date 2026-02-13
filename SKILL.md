---
name: encoding-guard
description: Prevent Chinese mojibake before file writes using a strict preflight gate. Use this skill when the agent is about to create, edit, or delete repo-tracked files, and enforce encoding policy checks at that execution step (not keyword-triggered by user text).
---

# Encoding Guard

Enforce a write-time gate that blocks risky encoding operations before mutation.

## Mandatory Workflow (Step-Triggered)

1. Resolve repository root.
2. Ensure project policy exists:

```bash
python scripts/encoding_guard.py init-policy --root <repo>
```

3. Run preflight gate before any file mutation:

```bash
python scripts/encoding_guard.py preflight --root <repo> --policy <repo>/.encoding-policy.json --files <file1> <file2> ...
```

4. Block write operations when preflight exit code is `2`.
5. Validate pending write content via `--stdin-text` (recommended for all mutations; mandatory for brand-new files).
6. Proceed with write operations only when preflight exit code is `0`.

## Command Reference

### Initialize policy

```bash
python scripts/encoding_guard.py init-policy --root <repo>
```

- Auto-create `<repo>/.encoding-policy.json` when missing.
- Use `--force` to overwrite.

### Scan repository

```bash
python scripts/encoding_guard.py scan --root <repo> --policy <policy-path>
```

- Generate risk report.
- Use `--json` for machine-readable output.

### Preflight gate

```bash
python scripts/encoding_guard.py preflight --root <repo> --policy <policy-path>
```

- Exit `0`: pass.
- Exit `2`: block (high-risk findings).
- Exit `1`: execution/policy error.

Optional pending-write text check:

```bash
cat <candidate_text_file> | python scripts/encoding_guard.py preflight --root <repo> --policy <policy-path> --stdin-text --stdin-label pending_patch
```

`--stdin-text` now blocks suspicious placeholder runs like `??`, `???`, `????` to prevent accidental Chinese-to-question-mark corruption.

## Gate Deployment Across Repositories

Use the sync script to upsert AGENTS gate blocks in all discovered repositories:

```bash
python scripts/sync_agents_gate.py --roots E:\_workSpace E:\gits E:\Git --extra-repo E:\_workSpace\quant
```

This script inserts mandatory write-before commands into each repo `AGENTS.md`.

## Policy and Rules

Read detailed field definitions in `references/policy-schema.md`.

Read blocker/warning logic in `references/preflight-rules.md`.
