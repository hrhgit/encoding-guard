# Encoding Policy Schema

Policy file path: `<repo>/.encoding-policy.json`

## Example

```json
{
  "version": 1,
  "default_encoding": "utf-8",
  "allowed_encodings": ["utf-8", "utf-8-sig"],
  "include_globs": ["**/*.py", "**/*.md", "**/*.toml", "**/*.json", "**/*.yaml", "**/*.yml", "**/*.txt", "**/*.csv"],
  "exclude_globs": ["**/.git/**", "**/.venv/**", "**/node_modules/**", "**/__pycache__/**", "**/dist/**", "**/build/**"],
  "high_risk_tokens": ["\uFFFD", "\u951F\u65A4\u62F7"],
  "warn_tokens": ["\u9365", "\u93C2", "\u7487", "\u951B", "\u9225", "\u9286", "\u9983"],
  "question_placeholder_regex": "\\?{2,}",
  "enforcement": {
    "mode": "block",
    "warn_threshold": 1,
    "block_threshold": 1
  }
}
```

## Field meanings

- `allowed_encodings`: only these decoded encodings are compliant.
- `include_globs`: file patterns to inspect.
- `exclude_globs`: ignored paths (wins over include).
- `high_risk_tokens`: any hit is blocker.
- `warn_tokens`: warning token density triggers warning/block by threshold.
- `question_placeholder_regex`: regex for placeholder question-mark runs; used to block pending patch text via `--stdin-text`.
- `enforcement.mode`: keep `block` for strict prevention.

## Recommended defaults

- Keep `allowed_encodings` as `["utf-8", "utf-8-sig"]` for Windows compatibility.
- Keep both thresholds at `1` for strict zero-tolerance blocking.

## Customization examples

- Strict UTF-8 only:
  - Set `allowed_encodings` to `["utf-8"]`.
- Broader include scope:
  - Add patterns like `"*.ini"`, `"**/*.ini"`.
- Narrower scope for write-time gate:
  - Keep policy default, but call preflight with `--files` for planned mutation paths only.
- Stronger warnings as blockers:
  - Keep `warn_threshold=1`, `block_threshold=1` (default).
