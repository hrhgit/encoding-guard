# Encoding Guard

<p align="center">
  <a href="./README.md">简体中文</a>
  |
  English
</p>

`encoding-guard` is a minimal skill with one primary goal: **Chinese-first output**.  
Encoding policy is a safeguard to avoid mojibake and keep Chinese output stable.

## Core Actions

1. Initialize a minimal policy file
2. Resolve output encoding before Chinese output

## Quick Start

```bash
python scripts/encoding_guard.py init-policy --root <repo>
python scripts/encoding_guard.py get-output-encoding --root <repo>
```

- Default policy file: `<repo>/.encoding-policy.json`
- Default policy content:

```json
{"encoding":"utf-8"}
```

## Behavior Rules

- Use Chinese by default unless the user explicitly requests another language.
- Do not switch to English as an encoding workaround.
- If encoding resolution fails, fall back to `utf-8` and continue in Chinese.
