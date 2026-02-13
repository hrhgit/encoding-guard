# Preflight Rules

This skill is prevention-only.

## Block conditions

1. Decoded encoding is not in `allowed_encodings`.
2. Any `high_risk_tokens` found.
3. Total `warn_tokens` count reaches `block_threshold`.
4. `--stdin-text` contains placeholder question-mark runs matched by `question_placeholder_regex` (default: `\?{2,}`).
5. File read/decode failure for included text files.

## Warning conditions

- `warn_tokens` count reaches `warn_threshold` but below `block_threshold`.
- Current file content contains placeholder question-mark runs matched by `question_placeholder_regex`.

## Skip conditions

- Path matched by `exclude_globs`.
- File not matched by `include_globs`.
- Binary file.
- File larger than scan guard size (2MB by default).

## Exit codes

- `0`: preflight pass
- `2`: preflight block
- `1`: execution/policy error

## Failure example

A pending patch text contains `????`:

- `question_placeholder_regex` hit count > 0
- preflight returns `2`
- write operation must stop

## Scope recommendation

- Prefer `--files <planned mutations>` for write-time gating to avoid unrelated historical files blocking unrelated edits.
- Use full-repo `scan` for periodic audits, not for every single write step.
