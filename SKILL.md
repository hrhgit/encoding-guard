---
name: encoding-guard
description: Minimal Chinese-first output helper. Keep responses in Chinese by default and resolve encoding to avoid mojibake.
---

# Encoding Guard

Keep this skill minimal. It only provides two actions.

## Goal

Primary goal: prioritize Chinese output.

Encoding control is a safeguard, not the end goal. The skill exists to keep Chinese readable and stable.

## Action 1: Create minimal policy file

Use this command:

```bash
python scripts/encoding_guard.py init-policy --root <repo>
```

- Default file path: `<repo>/.encoding-policy.json`
- File content is intentionally minimal:

```bash
{"encoding":"utf-8"}
```

## Action 2: Resolve output encoding before Chinese output

Before outputting Chinese text, call:

```bash
python scripts/encoding_guard.py get-output-encoding --root <repo>
```

- If policy file does not exist, it is created automatically with minimal content.
- The command returns the encoding string (default `utf-8`).

## Agent behavior

1. If user asks for encoding setup, run `init-policy`.
2. Language policy: output Chinese by default unless the user explicitly requests another language.
3. Before outputting Chinese text, run `get-output-encoding`.
4. Use returned encoding as output encoding guidance.
5. Do **not** switch to English as an encoding workaround.
6. If encoding resolution fails, fallback to `utf-8` and continue in Chinese.
7. This skill's top priority is Chinese-first output; anti-mojibake is the supporting mechanism.
