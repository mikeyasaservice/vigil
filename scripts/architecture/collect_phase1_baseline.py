#!/usr/bin/env python3
"""Reproduce source-only Phase 1 evidence without importing Vigil or accessing data.

Inventories are syntactic, not proof of runtime authorization. Refuse a changed
baseline so the checked-in evidence cannot silently describe another revision.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import io
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMIT = "0226200c476913b8bd5dff1df9bb221c6b147186"
OUT = ROOT / "docs/architecture/evidence"
SOURCE_ROOTS = ("core/", "services/", "infra/", "tools/", "tests/")
LOCKS = (
    ".python-version",
    "requirements.txt",
    "requirements.lock",
    "services/agent/package.json",
    "services/agent/package-lock.json",
    "services/medic/uv.lock",
    "clients/web/package-lock.json",
    "infra/helm/vigil/Chart.yaml",
    "infra/helm/vigil/Chart.lock",
    "infra/docker/docker-compose.yml",
    "core/storage/schema.snapshot.json",
)
TENANT_COLUMNS = {"tenant_id", "organization_id", "org_id"}


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def csv_text(fields: list[str], rows: list[dict]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def literal(node: ast.AST | None) -> str:
    return str(node.value) if isinstance(node, ast.Constant) else ""


def route_inventory(paths: list[str]) -> list[dict]:
    routes = []
    for name in paths:
        if not name.endswith(".py") or not name.startswith(
            ("core/", "services/api/", "tools/mcp/")
        ):
            continue
        tree = ast.parse((ROOT / name).read_text(), filename=name)
        prefixes = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in ("RouterMeta", "APIRouter"):
                    prefixes.update(
                        literal(k.value) for k in node.keywords if k.arg == "prefix"
                    )
        prefix = next(iter(prefixes)) if len(prefixes) == 1 else ""
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call) or not isinstance(
                    dec.func, ast.Attribute
                ):
                    continue
                method = dec.func.attr
                if method not in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                    "websocket",
                    "api_route",
                }:
                    continue
                if not dec.args or not isinstance(dec.args[0], ast.Constant):
                    continue
                routes.append(
                    {
                        "source": name,
                        "line": node.lineno,
                        "method": method.upper(),
                        "declared_prefix": prefix,
                        "local_path": literal(dec.args[0]),
                        "handler": node.name,
                        "classification": "requires_tenant_boundary_review",
                    }
                )
    return sorted(routes, key=lambda r: (r["source"], r["line"], r["method"]))


def build() -> dict[str, str]:
    # Documentation-only commits may advance HEAD without changing the baseline.
    # Source changes require a new audit, not silently regenerated old evidence.
    git("cat-file", "-e", f"{COMMIT}^{{commit}}")
    paths = git("ls-tree", "-r", "--name-only", COMMIT).splitlines()
    changed = git("diff", COMMIT, "--name-only", "--", *SOURCE_ROOTS, *LOCKS)
    if changed:
        raise SystemExit(f"Audited source differs from baseline:\n{changed}")
    snapshot = json.loads((ROOT / "core/storage/schema.snapshot.json").read_text())
    ddl = {}
    for name in paths:
        if name.startswith("infra/database/init/") and name.endswith(".sql"):
            for line, content in enumerate((ROOT / name).read_text().splitlines(), 1):
                match = re.search(
                    r"CREATE TABLE\s+(?:IF NOT EXISTS\s+)?([\w]+)", content, re.I
                )
                if match:
                    ddl.setdefault(match[1], []).append(f"{name}:{line}")
    tables = [
        {
            "table": table,
            "column_count": len(columns),
            "tenant_columns": ";".join(sorted(TENANT_COLUMNS.intersection(columns))),
            "ddl_sources": ";".join(ddl.get(table, [])),
            "classification": "instance_scoped_no_tenant_column",
        }
        for table, columns in sorted(snapshot.items())
    ]
    routes = route_inventory(paths)
    hashes = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in LOCKS}
    manifest = {
        "repository": "https://github.com/mikeyasaservice/vigil",
        "commit": COMMIT,
        "git_tree": git("rev-parse", f"{COMMIT}^{{tree}}"),
        "method": "static source inventory; no application imports or runtime claims",
        "table_count": len(tables),
        "tables_with_tenant_columns": sum(
            bool(row["tenant_columns"]) for row in tables
        ),
        "route_declaration_count": len(routes),
        "route_limitations": "Decorators only; prefixes are hints. Runtime mounts, aliases, MCP registration and dynamic routes need deployed inventory. No per-route auth verdict inferred.",
        "sha256": hashes,
    }
    return {
        "baseline.json": json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        "tables.csv": csv_text(list(tables[0]), tables),
        "routes.csv": csv_text(list(routes[0]), routes),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Compare without writing")
    args = parser.parse_args()
    files = build()
    if args.check:
        stale = [
            name
            for name, content in files.items()
            if not (OUT / name).is_file() or (OUT / name).read_text() != content
        ]
        if stale:
            raise SystemExit(f"Evidence missing or stale: {', '.join(stale)}")
    else:
        OUT.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            (OUT / name).write_text(content)
    print(
        f"Phase 1 baseline evidence {'verified' if args.check else 'written'} ({len(files)} files)"
    )


if __name__ == "__main__":
    main()
