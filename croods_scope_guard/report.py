"""Deterministic, template-based reports: no model or remote service required."""

from __future__ import annotations

import html
import json
from pathlib import Path


def source_link(audit: dict, location: str) -> str | None:
    if not audit.get("remote") or not audit.get("commit"):
        return None
    path, line = location.rsplit(":", 1)
    return f"{audit['remote']}/blob/{audit['commit']}/{path}#L{line}"


def markdown(audit: dict) -> str:
    lines = [
        "# Croods Scope Guard | Repository audit", "",
        f"Repository: {audit.get('remote') or audit['repository']}",
        f"Commit: {audit.get('commit') or 'unavailable'}", "",
        "## Objective", "",
        "Identify places where Croods may return an unfiltered query when it cannot establish the required tenant or owner relationship. The Ruby guard included with this package can reject such queries at runtime.", "",
        "## Method and result", "",
        f"Checked {len(audit['checks_run'])} source rules; found {len(audit['findings'])} observations. This was a static source and schema review. No Rails requests were executed.", "",
        "## Findings", "",
    ]
    if not audit["findings"]:
        lines.extend(["No matching fallback was found. This does not prove that authorization is secure.", ""])
    for item in audit["findings"]:
        url = source_link(audit, item["location"])
        location = f"[{item['location']}]({url})" if url else f"`{item['location']}`"
        lines.extend([
            f"### {item['id']} | {item['title']}", "",
            f"Status: `{item['status']}`. Potential severity if its conditions hold: `{item['severity']}`.",
            f"Source: {location}", "",
            f"**What the code does:** {item['evidence']}", "",
            f"**When it matters:** {item['condition']}", "",
            f"**Recommended action:** {item['remedy']}", "",
        ])
    lines.extend(["## Example application's resources", "",
                  "The paths below are inferred from the checked-in schema. They are not runtime authorization results.", ""])
    if audit["resources"]:
        lines.extend(["| Resource | Inferred path to tenant | Interpretation |", "| --- | --- | --- |"])
        for row in audit["resources"]:
            route = " → ".join(row["tenant_path"] or []) or "None found"
            lines.append(f"| `{row['resource']}` | {route} | {row['status']} |")
    else:
        lines.append("No tenant-initialized resource/schema pair was found.")
    lines.extend(["", "## Practical fix", "",
                  "1. Add the included Ruby guard to the Rails application. It scopes the tenant model to its own ID and raises an explicit exception when a required association cannot be established.",
                  "2. Mark intentionally shared resource models explicitly. Verify each exception with a Rails request test.",
                  "3. Create two tenants and verify that users cannot list, show, update or delete the other's records.", "",
                  "## Limits", ""])
    lines.extend(f"- {limit}" for limit in audit["limitations"])
    return "\n".join(lines) + "\n"


def html_report(audit: dict) -> str:
    # Embed only escaped output, with no network dependencies or JavaScript.
    esc = html.escape
    cards = []
    for finding in audit["findings"]:
        url = source_link(audit, finding["location"])
        loc = (f'<a href="{esc(url, quote=True)}">{esc(finding["location"])}</a>'
               if url else esc(finding["location"]))
        cards.append(f'<section class="card"><div class="meta">{esc(finding["id"])} · {esc(finding["status"])} · {esc(finding["severity"])}</div>'
                     f'<h2>{esc(finding["title"])}</h2><p class="source">{loc}</p>'
                     f'<h3>Observed code</h3><p>{esc(finding["evidence"])}</p>'
                     f'<h3>Condition for impact</h3><p>{esc(finding["condition"])}</p>'
                     f'<h3>Suggested fix</h3><p>{esc(finding["remedy"])}</p></section>')
    rows = "".join(f'<tr><td>{esc(r["resource"])}</td><td>{esc(" → ".join(r["tenant_path"] or []) or "None found")}</td><td>{esc(r["status"])}</td></tr>'
                   for r in audit["resources"])
    limits = "".join(f"<li>{esc(item)}</li>" for item in audit["limitations"])
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Croods Scope Guard | Repository audit</title><style>
body{{font:16px/1.58 system-ui,-apple-system,Segoe UI,sans-serif;background:#f6f7fa;color:#15263b;margin:0}}main{{max-width:900px;margin:auto;padding:42px 22px 90px}}
h1{{font-size:2.2rem;margin:.15em 0}}h2{{font-size:1.24rem;margin:.3em 0}}h3{{font-size:.9rem;margin:1.3em 0 .1em}}p{{margin:.35em 0 1em}}
.eyebrow,.meta{{color:#426486;font-size:.85rem;font-weight:700;letter-spacing:.03em;text-transform:uppercase}}
.lead{{color:#4b6076;font-size:1.05rem}}.card,.panel{{background:white;border:1px solid #dfe5ec;border-radius:12px;padding:22px;margin:16px 0;box-shadow:0 2px 8px #162b4008}}
.source{{font-family:monospace;font-size:.85rem;overflow-wrap:anywhere}}a{{color:#075db5}}table{{border-collapse:collapse;width:100%;background:white}}td,th{{text-align:left;border-bottom:1px solid #e3e8ed;padding:10px 12px}}
.table-wrap{{overflow-x:auto}}.badge{{display:inline-block;padding:7px 11px;background:#fff0d5;border-radius:6px;color:#764a00;font-weight:650}}
</style></head><body><main><div class="eyebrow">Repository analysis · Static review</div><h1>Croods Scope Guard</h1>
<p class="lead">Objective: identify when Croods can return an unfiltered query instead of enforcing tenant or owner scope.</p>
<p><strong>Repository:</strong> {esc(audit.get('remote') or audit['repository'])}<br><strong>Commit:</strong> {esc(audit.get('commit') or 'unavailable')}</p>
<p class="badge">{len(audit['checks_run'])} checks · {len(audit['findings'])} observations · No Rails requests executed</p>
<h2>Code findings</h2>{''.join(cards) or '<p>No matching source patterns found.</p>'}
<section class="panel"><h2>Example application: tenant paths</h2><p>Inferred from the database schema; dynamic policies and associations require Rails tests.</p>
<div class="table-wrap"><table><thead><tr><th>Resource</th><th>Possible path</th><th>Result</th></tr></thead><tbody>{rows}</tbody></table></div></section>
<section class="panel"><h2>Recommended implementation</h2><p>Install the accompanying Ruby guard, which scopes the tenant model to its own ID and raises on missing required paths. Explicitly declare models intended for global access. Test with two tenants using request specs.</p>
<h2>Evidence limits</h2><ul>{limits}</ul></section></main></body></html>'''


def save(audit: dict, directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    outputs = {
        "report.md": markdown(audit),
        "report.html": html_report(audit),
        "report.json": json.dumps(audit, indent=2, ensure_ascii=False) + "\n",
    }
    for name, content in outputs.items():
        (directory / name).write_text(content, encoding="utf-8")
    return [directory / name for name in outputs]
