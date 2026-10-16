"""CLI entry point: `python -m scanner <config.json>`."""
from __future__ import annotations

import argparse
import json
import sys

from .core import render_markdown, scan_file


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanner",
        description="Scan MCP/tool description JSON files for prompt-injection payloads.",
    )
    p.add_argument("config", help="Path to the JSON config file to scan.")
    p.add_argument(
        "--report",
        metavar="FILE",
        help="Write a markdown report to FILE (default: stdout).",
    )
    p.add_argument(
        "--format",
        choices=("text", "markdown", "json"),
        default="text",
        help="Output format for findings (default: text).",
    )
    p.add_argument(
        "--fail-on",
        choices=("clean", "suspicious", "poisoned"),
        default="poisoned",
        help="Exit non-zero when verdict is at least this bad (default: poisoned).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        report = scan_file(args.config)
    except FileNotFoundError:
        print(f"error: file not found: {args.config}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON in {args.config}: {exc}", file=sys.stderr)
        return 2

    sev = report.by_severity
    sev_summary = ", ".join(f"{k}={v}" for k, v in sorted(sev.items())) or "none"

    if args.format == "markdown":
        output = render_markdown(report)
    elif args.format == "json":
        output = json.dumps(
            {
                "target": report.target,
                "tools_scanned": report.tools_scanned,
                "verdict": report.verdict,
                "total_score": report.total_score,
                "findings": [
                    {
                        "tool": f.tool_name,
                        "field": f.field,
                        "pattern": f.pattern_id,
                        "severity": f.severity,
                        "description": f.description,
                        "match": f.match,
                        "score": f.score,
                    }
                    for f in report.findings
                ],
            },
            indent=2,
        )
    else:
        parts = [
            f"Target:        {report.target}",
            f"Tools scanned: {report.tools_scanned}",
            f"Findings:      {len(report.findings)} ({sev_summary})",
            f"Risk score:    {report.total_score}",
            f"Verdict:       {report.verdict}",
        ]
        for f in report.findings:
            parts.append(f"  [{f.severity.upper()}] {f.tool_name}: {f.pattern_id} -> `{f.match}`")
        output = "\n".join(parts)

    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(report))
        print(f"Markdown report written to {args.report}")
    print(output)

    verdict_rank = {"CLEAN": 0, "SUSPICIOUS": 1, "POISONED": 2}
    fail_rank = {"clean": 1, "suspicious": 1, "poisoned": 2}[args.fail_on]
    return 1 if verdict_rank[report.verdict] >= fail_rank else 0


if __name__ == "__main__":
    raise SystemExit(main())
