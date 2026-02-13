#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

DEFAULT_ENCODING = "utf-8"


def default_policy_path(root: Path) -> Path:
    return root / ".encoding-policy.json"


def make_policy(encoding: str) -> dict:
    return {"encoding": encoding}


def write_policy(path: Path, encoding: str, force: bool = False) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        return False
    policy = make_policy(encoding)
    path.write_text(json.dumps(policy, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    return True


def read_policy_encoding(path: Path, default_encoding: str) -> str:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default_encoding

    if isinstance(raw, dict):
        value = raw.get("encoding")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return default_encoding


def ensure_policy_and_get_encoding(path: Path, default_encoding: str) -> tuple[str, bool]:
    created = False
    if not path.exists():
        write_policy(path, default_encoding, force=False)
        created = True

    encoding = read_policy_encoding(path, default_encoding)
    # Repair malformed policy into canonical minimal shape.
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raw = None
    if raw != make_policy(encoding):
        write_policy(path, encoding, force=True)

    return encoding, created


def cmd_init_policy(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = Path(args.policy).resolve() if args.policy else default_policy_path(root)
    created = write_policy(policy_path, args.encoding, force=args.force)
    payload = {
        "action": "init-policy",
        "created": created,
        "policy": str(policy_path),
        "encoding": args.encoding,
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print(f"[OK] {'Created' if created else 'Exists'} policy: {policy_path} ({args.encoding})")
    return 0


def cmd_get_output_encoding(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = Path(args.policy).resolve() if args.policy else default_policy_path(root)
    encoding, created = ensure_policy_and_get_encoding(policy_path, args.default)
    payload = {
        "action": "get-output-encoding",
        "policy": str(policy_path),
        "encoding": encoding,
        "created": created,
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print(encoding)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Minimal encoding policy helper.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init-policy", help="Create minimal .encoding-policy.json")
    p_init.add_argument("--root", required=True, help="Workspace root")
    p_init.add_argument("--policy", help="Policy file path (default: <root>/.encoding-policy.json)")
    p_init.add_argument("--encoding", default=DEFAULT_ENCODING, help="Encoding to store in policy")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing policy")
    p_init.add_argument("--json", action="store_true", help="Output JSON")
    p_init.set_defaults(func=cmd_init_policy)

    p_get = sub.add_parser(
        "get-output-encoding",
        help="Return encoding for Chinese output; create minimal policy if missing",
    )
    p_get.add_argument("--root", required=True, help="Workspace root")
    p_get.add_argument("--policy", help="Policy file path (default: <root>/.encoding-policy.json)")
    p_get.add_argument("--default", default=DEFAULT_ENCODING, help="Fallback encoding")
    p_get.add_argument("--json", action="store_true", help="Output JSON")
    p_get.set_defaults(func=cmd_get_output_encoding)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except Exception as exc:
        if getattr(args, "json", False):
            print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        else:
            print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
