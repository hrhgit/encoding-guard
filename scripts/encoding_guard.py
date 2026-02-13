#!/usr/bin/env python3
import argparse
import codecs
import fnmatch
import io
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Any

DEFAULT_POLICY = {
    "version": 1,
    "default_encoding": "utf-8",
    "allowed_encodings": ["utf-8", "utf-8-sig"],
    "include_globs": [
        "*.py", "**/*.py",
        "*.md", "**/*.md",
        "*.toml", "**/*.toml",
        "*.json", "**/*.json",
        "*.yaml", "**/*.yaml",
        "*.yml", "**/*.yml",
        "*.txt", "**/*.txt",
        "*.csv", "**/*.csv",
    ],
    "exclude_globs": [
        ".git/**", "**/.git/**",
        ".venv/**", "**/.venv/**",
        "venv/**", "**/venv/**",
        "node_modules/**", "**/node_modules/**",
        "__pycache__/**", "**/__pycache__/**",
        "dist/**", "**/dist/**",
        "build/**", "**/build/**",
    ],
    "high_risk_tokens": ["\uFFFD", "\u951F\u65A4\u62F7"],
    "warn_tokens": ["\u9365", "\u93C2", "\u7487", "\u951B", "\u9225", "\u9286", "\u9983"],
    "question_placeholder_regex": r"\?{2,}",
    "enforcement": {
        "mode": "block",
        "warn_threshold": 1,
        "block_threshold": 1,
    },
}

CANDIDATE_DECODINGS = ["utf-8", "utf-8-sig", "gbk", "cp936", "latin1"]
MAX_FILE_BYTES = 2 * 1024 * 1024
PRUNE_DIR_NAMES = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
if sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
if sys.stdin.encoding and sys.stdin.encoding.lower() != "utf-8":
    sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8")


def _deep_merge(base: Any, override: Any) -> Any:
    if isinstance(base, dict) and isinstance(override, dict):
        out = dict(base)
        for k, v in override.items():
            out[k] = _deep_merge(out[k], v) if k in out else v
        return out
    return override


def _validate_policy(policy: Dict[str, Any]) -> None:
    required = [
        "version", "default_encoding", "allowed_encodings", "include_globs", "exclude_globs",
        "high_risk_tokens", "warn_tokens", "question_placeholder_regex", "enforcement"
    ]
    for key in required:
        if key not in policy:
            raise ValueError(f"policy missing required key: {key}")

    if not isinstance(policy["allowed_encodings"], list) or not policy["allowed_encodings"]:
        raise ValueError("allowed_encodings must be a non-empty list")
    for enc in policy["allowed_encodings"]:
        try:
            codecs.lookup(enc)
        except LookupError as exc:
            raise ValueError(f"unsupported encoding in allowed_encodings: {enc}") from exc

    if not isinstance(policy["include_globs"], list) or not policy["include_globs"]:
        raise ValueError("include_globs must be a non-empty list")
    if not isinstance(policy["exclude_globs"], list):
        raise ValueError("exclude_globs must be a list")

    enf = policy["enforcement"]
    if not isinstance(enf, dict):
        raise ValueError("enforcement must be an object")
    mode = enf.get("mode", "block")
    if mode not in {"block", "warn"}:
        raise ValueError("enforcement.mode must be 'block' or 'warn'")
    for key in ["warn_threshold", "block_threshold"]:
        value = enf.get(key)
        if not isinstance(value, int) or value < 1:
            raise ValueError(f"enforcement.{key} must be integer >= 1")

    placeholder_regex = policy.get("question_placeholder_regex")
    if not isinstance(placeholder_regex, str) or not placeholder_regex:
        raise ValueError("question_placeholder_regex must be a non-empty string")
    try:
        re.compile(placeholder_regex)
    except re.error as exc:
        raise ValueError(f"invalid question_placeholder_regex: {exc}") from exc


def default_policy_path(root: Path) -> Path:
    return root / ".encoding-policy.json"


def init_policy(path: Path, force: bool = False) -> Tuple[bool, Path]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        return False, path
    path.write_text(json.dumps(DEFAULT_POLICY, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return True, path


def load_policy(path: Path) -> Dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    policy = _deep_merge(DEFAULT_POLICY, raw)
    _validate_policy(policy)
    return policy


def norm_rel(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _pattern_variants(pattern: str) -> List[str]:
    variants = [pattern]
    if pattern.startswith("**/"):
        variants.append(pattern[3:])
    return list(dict.fromkeys(variants))


def glob_match(rel: str, patterns: List[str]) -> bool:
    rel = rel.replace("\\", "/")
    for pattern in patterns:
        for cand in _pattern_variants(pattern):
            if fnmatch.fnmatch(rel, cand):
                return True
    return False


def is_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    if b"\x00" in sample:
        return True
    ctrl = 0
    for b in sample:
        if b in (9, 10, 13):
            continue
        if b < 32:
            ctrl += 1
    return (ctrl / max(1, len(sample))) > 0.30


def detect_encoding(data: bytes) -> Tuple[str, str]:
    if data.startswith(codecs.BOM_UTF8):
        return data.decode("utf-8-sig"), "utf-8-sig"

    for enc in CANDIDATE_DECODINGS:
        try:
            text = data.decode(enc)
            # normalize utf-8-sig without BOM to utf-8 label
            if enc == "utf-8-sig":
                return text, "utf-8"
            return text, enc
        except Exception:
            continue

    raise UnicodeDecodeError("unknown", b"", 0, 1, "unable to decode with candidate encodings")


def token_count(text: str, tokens: List[str]) -> Dict[str, int]:
    return {token: text.count(token) for token in tokens if token}


def regex_hit_count(text: str, pattern: str) -> int:
    if not pattern:
        return 0
    return len(re.findall(pattern, text))


def evaluate_tokens(high_counts: Dict[str, int], warn_counts: Dict[str, int], policy: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    blockers: List[str] = []
    warnings: List[str] = []

    high_total = sum(high_counts.values())
    warn_total = sum(warn_counts.values())

    if high_total > 0:
        blockers.append(f"high-risk tokens found: {high_total}")

    block_threshold = int(policy["enforcement"]["block_threshold"])
    warn_threshold = int(policy["enforcement"]["warn_threshold"])

    if warn_total >= block_threshold:
        blockers.append(f"warning-token count {warn_total} >= block_threshold {block_threshold}")
    elif warn_total >= warn_threshold:
        warnings.append(f"warning-token count {warn_total} >= warn_threshold {warn_threshold}")

    return blockers, warnings


def analyze_text_block(text: str, label: str, policy: Dict[str, Any]) -> Dict[str, Any]:
    high_counts = token_count(text, policy["high_risk_tokens"])
    warn_counts = token_count(text, policy["warn_tokens"])
    blockers, warnings = evaluate_tokens(high_counts, warn_counts, policy)
    placeholder_hits = regex_hit_count(text, policy.get("question_placeholder_regex", r"\?{2,}"))

    if placeholder_hits > 0:
        blockers.append(f"placeholder question-mark runs found: {placeholder_hits}")

    status = "ok"
    if blockers:
        status = "block"
    elif warnings:
        status = "warn"

    return {
        "path": label,
        "status": status,
        "encoding": "virtual-text",
        "blockers": blockers,
        "warnings": warnings,
        "token_counts": {
            "high_risk": high_counts,
            "warn": warn_counts,
            "question_placeholder_regex": placeholder_hits,
        },
    }


def analyze_file(path: Path, root: Path, policy: Dict[str, Any]) -> Dict[str, Any]:
    rel = norm_rel(path, root)

    if glob_match(rel, policy["exclude_globs"]):
        return {"path": rel, "status": "skipped", "reason": "excluded-by-policy"}

    if not glob_match(rel, policy["include_globs"]):
        return {"path": rel, "status": "skipped", "reason": "not-in-include-globs"}

    try:
        data = path.read_bytes()
    except Exception as exc:
        return {
            "path": rel,
            "status": "block",
            "encoding": "unknown",
            "blockers": [f"read error: {exc}"],
            "warnings": [],
            "token_counts": {"high_risk": {}, "warn": {}},
        }

    if len(data) > MAX_FILE_BYTES:
        return {"path": rel, "status": "skipped", "reason": f"file-too-large>{MAX_FILE_BYTES}"}

    if is_binary(data):
        return {"path": rel, "status": "skipped", "reason": "binary"}

    try:
        text, detected_encoding = detect_encoding(data)
    except Exception as exc:
        return {
            "path": rel,
            "status": "block",
            "encoding": "unknown",
            "blockers": [f"decode error: {exc}"],
            "warnings": [],
            "token_counts": {"high_risk": {}, "warn": {}},
        }

    blockers: List[str] = []
    warnings: List[str] = []

    if detected_encoding not in policy["allowed_encodings"]:
        blockers.append(f"encoding '{detected_encoding}' not in allowed_encodings {policy['allowed_encodings']}")

    high_counts = token_count(text, policy["high_risk_tokens"])
    warn_counts = token_count(text, policy["warn_tokens"])
    b2, w2 = evaluate_tokens(high_counts, warn_counts, policy)
    blockers.extend(b2)
    warnings.extend(w2)
    placeholder_hits = regex_hit_count(text, policy.get("question_placeholder_regex", r"\?{2,}"))
    if placeholder_hits > 0:
        warnings.append(f"placeholder question-mark runs found: {placeholder_hits} (detected in current file content)")

    status = "ok"
    if blockers:
        status = "block"
    elif warnings:
        status = "warn"

    return {
        "path": rel,
        "status": status,
        "encoding": detected_encoding,
        "blockers": blockers,
        "warnings": warnings,
        "token_counts": {
            "high_risk": high_counts,
            "warn": warn_counts,
            "question_placeholder_regex": placeholder_hits,
        },
    }


def collect_targets(root: Path, files: List[str] = None) -> List[Path]:
    if files:
        targets: List[Path] = []
        for item in files:
            p = Path(item)
            if not p.is_absolute():
                p = root / p
            if p.exists() and p.is_file():
                targets.append(p.resolve())
        return sorted(set(targets))

    results: List[Path] = []
    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in PRUNE_DIR_NAMES]
        base = Path(current_root)
        for fn in filenames:
            results.append((base / fn).resolve())
    return results


def summarize(results: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {"ok": 0, "warn": 0, "block": 0, "skipped": 0}
    for item in results:
        status = item.get("status", "skipped")
        if status in summary:
            summary[status] += 1
    summary["total"] = len(results)
    return summary


def run_scan(root: Path, policy_path: Path, files: List[str], auto_init_policy: bool) -> Dict[str, Any]:
    if auto_init_policy and not policy_path.exists():
        init_policy(policy_path, force=False)

    if not policy_path.exists():
        raise FileNotFoundError(f"policy file not found: {policy_path}")

    policy = load_policy(policy_path)
    targets = collect_targets(root, files=files)
    results = [analyze_file(p, root, policy) for p in targets]

    return {
        "root": str(root),
        "policy": str(policy_path),
        "summary": summarize(results),
        "results": results,
    }


def print_human_report(report: Dict[str, Any], title: str) -> None:
    s = report["summary"]
    print(f"{title}: {report['root']}")
    print(f"Policy: {report['policy']}")
    print(f"Summary => total={s['total']} ok={s['ok']} warn={s['warn']} block={s['block']} skipped={s['skipped']}")

    blockers = [r for r in report["results"] if r.get("status") == "block"]
    if blockers:
        print("Blockers:")
        for item in blockers:
            print(f"  - {item['path']}")
            for msg in item.get("blockers", []):
                print(f"      * {msg}")


def cmd_init_policy(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = Path(args.policy).resolve() if args.policy else default_policy_path(root)
    created, path = init_policy(policy_path, force=args.force)

    payload = {"action": "init-policy", "created": created, "policy": str(path)}
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"[OK] {'Created' if created else 'Exists'} policy: {path}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = Path(args.policy).resolve() if args.policy else default_policy_path(root)
    report = run_scan(root, policy_path, files=args.files, auto_init_policy=args.auto_init_policy)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_human_report(report, "Scan")
    return 0


def cmd_preflight(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = Path(args.policy).resolve() if args.policy else default_policy_path(root)

    report = run_scan(root, policy_path, files=args.files, auto_init_policy=args.auto_init_policy)

    if args.stdin_text:
        policy = load_policy(policy_path)
        text = sys.stdin.read()
        report["results"].append(analyze_text_block(text, args.stdin_label, policy))
        report["summary"] = summarize(report["results"])

    blocked = report["summary"]["block"] > 0

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_human_report(report, "Preflight")
        print("Result:", "BLOCK" if blocked else "PASS")

    return 2 if blocked else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Encoding preflight gate (prevention only).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init-policy", help="Create default .encoding-policy.json")
    p_init.add_argument("--root", required=True, help="Repository root")
    p_init.add_argument("--policy", help="Policy file path (default: <root>/.encoding-policy.json)")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing policy")
    p_init.add_argument("--json", action="store_true", help="Output JSON")
    p_init.set_defaults(func=cmd_init_policy)

    p_scan = sub.add_parser("scan", help="Scan files and report risks")
    p_scan.add_argument("--root", required=True, help="Repository root")
    p_scan.add_argument("--policy", help="Policy file path (default: <root>/.encoding-policy.json)")
    p_scan.add_argument("--files", nargs="*", help="Optional file list (relative to root or absolute)")
    p_scan.add_argument("--json", action="store_true", help="Output JSON")
    p_scan.add_argument("--auto-init-policy", action="store_true", default=True, help="Auto-create default policy if missing")
    p_scan.set_defaults(func=cmd_scan)

    p_pf = sub.add_parser("preflight", help="Pre-write gate; block on high-risk findings")
    p_pf.add_argument("--root", required=True, help="Repository root")
    p_pf.add_argument("--policy", help="Policy file path (default: <root>/.encoding-policy.json)")
    p_pf.add_argument("--files", nargs="*", help="Optional file list (relative to root or absolute)")
    p_pf.add_argument("--stdin-text", action="store_true", help="Check text from stdin as pending-write content")
    p_pf.add_argument("--stdin-label", default="__stdin__", help="Label for stdin text report")
    p_pf.add_argument("--json", action="store_true", help="Output JSON")
    p_pf.add_argument("--auto-init-policy", action="store_true", default=True, help="Auto-create default policy if missing")
    p_pf.set_defaults(func=cmd_preflight)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:
        payload = {"error": str(exc)}
        if getattr(args, "json", False):
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
