"""Command-line entry point for a read-only Croods repository audit."""

import argparse
from pathlib import Path

from .audit import audit
from .report import save


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Scan Croods authorization scopes and write HTML, Markdown, JSON reports")
    parser.add_argument("repository", type=Path, help="Local Croods git checkout")
    parser.add_argument("--report-dir", type=Path, default=Path("croods-scope-report"))
    parser.add_argument("--fail-on-risk", action="store_true", help="Exit 2 when a source pattern is found")
    args = parser.parse_args(argv)
    try:
        result = audit(args.repository)
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Audit failed: {exc}\n")
    outputs = save(result, args.report_dir)
    print(f"Checked {len(result['checks_run'])} rules; found {len(result['findings'])} observations.")
    for output in outputs:
        print(output.resolve())
    return 2 if args.fail_on_risk and result["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
