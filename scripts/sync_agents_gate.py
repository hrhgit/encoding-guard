#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import List, Set

BEGIN_MARKER = "<!-- encoding-guard:begin -->"
END_MARKER = "<!-- encoding-guard:end -->"

SKILL_SCRIPT = r"C:\Users\32858\.codex\skills\encoding-guard\scripts\encoding_guard.py"


def discover_repos(roots: List[Path]) -> List[Path]:
    repos: Set[Path] = set()
    for root in roots:
        if not root.exists():
            continue
        for git_dir in root.rglob(".git"):
            if git_dir.is_dir():
                repos.add(git_dir.parent.resolve())
    return sorted(repos)


def render_gate_block(repo: Path) -> str:
    repo_s = str(repo)
    return "\n".join([
        BEGIN_MARKER,
        "## Encoding Guard Gate (Mandatory)",
        "Before any repo-tracked file mutation, run these commands:",
        f"`python \"{SKILL_SCRIPT}\" init-policy --root \"{repo_s}\"`",
        f"`python \"{SKILL_SCRIPT}\" preflight --root \"{repo_s}\" --policy \"{repo_s}\\.encoding-policy.json\" --files <file1> <file2> ...`",
        "If preflight exits with code `2`, stop and do not write files.",
        "For brand-new files, pipe pending content with --stdin-text as an additional check.",
        END_MARKER,
    ])


def upsert_gate(existing: str, block: str) -> str:
    if BEGIN_MARKER in existing and END_MARKER in existing:
        start = existing.index(BEGIN_MARKER)
        end = existing.index(END_MARKER) + len(END_MARKER)
        return existing[:start].rstrip() + "\n\n" + block + "\n"

    if existing.strip():
        return existing.rstrip() + "\n\n" + block + "\n"

    return "# Repository AGENTS\n\n" + block + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync Encoding Guard gate block into repo AGENTS.md files.")
    parser.add_argument("--roots", nargs="+", required=True, help="Root directories used to discover git repositories")
    parser.add_argument("--extra-repo", action="append", default=[], help="Additional repo roots to include even if not git")
    parser.add_argument("--dry-run", action="store_true", help="Show target repos without writing")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    roots = [Path(x).resolve() for x in args.roots]
    repos = discover_repos(roots)

    for repo in args.extra_repo:
        p = Path(repo).resolve()
        if p.exists() and p.is_dir():
            repos.append(p)

    repos = sorted(set(repos))
    updated = []

    for repo in repos:
        agents_path = repo / "AGENTS.md"
        current = agents_path.read_text(encoding="utf-8") if agents_path.exists() else ""
        next_text = upsert_gate(current, render_gate_block(repo))

        if not args.dry_run:
            agents_path.write_text(next_text, encoding="utf-8")
        updated.append(str(agents_path))

    payload = {
        "repo_count": len(repos),
        "updated_agents": updated,
        "dry_run": bool(args.dry_run),
    }

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Repos: {payload['repo_count']}")
        for p in updated:
            print(f"  - {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
