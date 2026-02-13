---
name: encoding-guard
description: Minimal encoding helper. Create a tiny workspace encoding policy file and resolve which encoding to use before outputting Chinese text.
---

# Encoding Guard

Keep this skill minimal. It only provides two actions.

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
2. Before outputting Chinese text, run `get-output-encoding`.
3. Use returned encoding as output encoding guidance.
