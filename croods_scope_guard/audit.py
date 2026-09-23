"""Conservative, source-backed Croods scope audit; does not execute application code."""

from __future__ import annotations

import re
import subprocess
from collections import deque
from pathlib import Path


def _location(root: Path, path: Path, line: int) -> str:
    return f"{path.relative_to(root).as_posix()}:{line}"


def _find_line(source: str, pattern: str) -> int | None:
    match = re.search(pattern, source, re.MULTILINE)
    return source.count("\n", 0, match.start()) + 1 if match else None


def _git_info(root: Path) -> tuple[str | None, str | None]:
    try:
        commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5, check=True,
        ).stdout.strip()
        remote = subprocess.run(
            ["git", "-C", str(root), "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=5, check=True,
        ).stdout.strip()
        if remote.startswith("git@github.com:"):
            remote = "https://github.com/" + remote.split(":", 1)[1]
        if remote.startswith("https://github.com/"):
            remote = remote.removesuffix(".git")
        else:
            remote = None
        return commit, remote
    except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired):
        return None, None


def _schema(root: Path) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    schema_paths = sorted(root.glob("**/db/schema.rb"))
    if not schema_paths:
        return {}, {}
    # Use the first application schema, and report that this is a static approximation.
    source = schema_paths[0].read_text(encoding="utf-8")
    tables: dict[str, list[str]] = {}
    edges: dict[str, list[str]] = {}
    table = None
    for line in source.splitlines():
        match = re.search(r'^\s*create_table ["\']([^"\']+)["\']', line)
        if match:
            table = match.group(1)
            tables[table] = []
            edges[table] = []
        elif table and re.match(r"^\s*end\s*$", line):
            table = None
        elif table:
            col = re.search(r'\bt\.\w+\s+["\']([^"\']+)["\']', line)
            if col:
                name = col.group(1)
                tables[table].append(name)
                reference = re.search(r':foreign_key\s*=>\s*\{\s*:references\s*=>\s*["\']([^"\']+)["\']', line)
                if name.endswith("_id") and reference and ":null=>false" in line:
                    edges[table].append(reference.group(1))
    return tables, edges


def _path_to_tenant(start: str, tenant: str, tables: dict, edges: dict) -> list[str] | None:
    if start == tenant:
        return [start]
    queue = deque([(start, [start])])
    seen = {start}
    while queue:
        current, path = queue.popleft()
        if f"{tenant[:-1] if tenant.endswith('s') else tenant}_id" in tables.get(current, []):
            return path + [tenant]
        for parent in edges.get(current, []):
            if parent == tenant:
                return path + [parent]
            if parent not in seen:
                seen.add(parent)
                queue.append((parent, path + [parent]))
    return None


def audit(root: str | Path) -> dict:
    root = Path(root).resolve()
    scope_path = root / "lib/croods/policy/scope.rb"
    if not scope_path.is_file():
        raise ValueError("Not a Croods repository: lib/croods/policy/scope.rb is missing")
    source = scope_path.read_text(encoding="utf-8")
    commit, remote = _git_info(root)
    findings = []
    checks = [
        ("CSG001", "tenant_scope", "Croods may leave tenant scoping unapplied", "tenant"),
        ("CSG002", "owner_scope", "Croods may leave owner scoping unapplied", "owner"),
    ]
    for code, method, title, target in checks:
        block = re.search(rf"^\s*def {method}\(scope\)(.*?)(?=^\s*def \w+|\Z)", source, re.MULTILINE | re.DOTALL)
        if not block:
            continue
        fallback = re.search(r"return\s+scope\s+if\s+path\.empty\?", block.group(1))
        if fallback:
            offset = block.start(1) + fallback.start()
            line = source.count("\n", 0, offset) + 1
            findings.append({
                "id": code, "status": "confirmed_source_pattern", "severity": "conditional_high",
                "title": title, "location": _location(root, scope_path, line),
                "evidence": "If the association path is empty, this method returns the original unfiltered scope.",
                "condition": f"Impact requires an authorized request to a resource intended to be restricted by {target}, with no path recognized by Croods.",
                "remedy": "Require an explicit scope policy; fail closed when a required path is missing.",
            })
    tenant = None
    initializers = sorted(root.glob("**/config/initializers/croods.rb"))
    for initializer in initializers:
        match = re.search(r"multi_tenancy_by:\s*:(\w+)", initializer.read_text(encoding="utf-8"))
        if match:
            tenant = match.group(1)
            break
    tables, edges = _schema(root)
    resources = []
    if tenant and tables:
        tenant_table = tenant + "s" if not tenant.endswith("s") else tenant
        for table in tables:
            candidates = list(root.glob(f"**/app/resources/{table}/resource.rb"))
            if not candidates:
                continue
            path = _path_to_tenant(table, tenant_table, tables, edges)
            resources.append({"resource": table, "tenant_path": path, "status":
                              "tenant_root" if table == tenant_table else
                              "path_found" if path else "no_required_fk_path_in_schema"})
        if tenant_table in tables and any(r["resource"] == tenant_table for r in resources) and findings:
            findings.append({
                "id": "CSG003", "status": "inferred_from_schema", "severity": "conditional_high",
                "title": "The tenant model itself is not restricted by its own ID",
                "location": _location(root, scope_path, _find_line(source, r"return scope if path\.empty\?") or 1),
                "evidence": f"The {tenant_table} table has no {tenant}_id column; the default association traversal has no self-tenant path.",
                "condition": "Whether cross-tenant access is unintended depends on the application's admin policy.",
                "remedy": f"For the {tenant_table} model, use where(id: current_tenant.id) unless access to every tenant is explicitly intended.",
            })
            show_tests = sorted(root.glob(f"**/spec/**/{tenant_table}/show_spec.rb"))
            if show_tests:
                spec_path = show_tests[0]
                spec_source = spec_path.read_text(encoding="utf-8")
                independent_tenant = re.search(rf"\blet\(:{tenant}\)\s+do\s+{tenant.capitalize()}\.create", spec_source)
                expected_success = re.search(r"have_http_status\(:ok\)", spec_source)
                if independent_tenant and expected_success:
                    findings.append({
                        "id": "CSG004", "status": "test_expectation_observed", "severity": "policy_dependent",
                        "title": "Demo test expects a successful request for a separately created tenant",
                        "location": _location(root, spec_path, spec_source.count("\n", 0, expected_success.start()) + 1),
                        "evidence": "The show spec creates a separate tenant and expects HTTP 200. The test's shared authentication fixture uses another tenant.",
                        "condition": "This can be intentional administrator behavior; review the product's intended administrator boundaries.",
                        "remedy": "If administrators are tenant-local, change the test to expect a denied request and scope the root tenant model by ID.",
                    })
    return {
        "tool": "Croods Scope Guard", "version": "0.1.0", "repository": str(root),
        "commit": commit, "remote": remote, "method": "static_source_and_schema_review",
        "runtime_executed": False, "tenant_name": tenant, "checks_run": [c[0] for c in checks],
        "findings": findings, "resources": resources,
        "limitations": [
            "Static findings are not proof of an exploitable security issue or a production incident.",
            "Schema traversal approximates Rails associations; dynamic associations and custom policy overrides require runtime tests.",
            "The audit does not read private application code or execute endpoint requests.",
        ],
    }
