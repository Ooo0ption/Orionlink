#!/usr/bin/env python3
"""Consolidates the three live-browser E2 reports into paper Table 4.

The E2 harnesses each write one JSON into benchmark/results/ and print only
their own figures, so reading Table 4 off them means opening three files and
knowing which column of each backs which row. This does that mapping in one
place and prints the table.

    ./benchmark/e2/summarize.py                    # profile from ORION_PROFILE
    ./benchmark/e2/summarize.py --profile paper
    ./benchmark/e2/summarize.py --markdown         # paste-ready
    ./benchmark/e2/summarize.py --components       # also the sub-measures

run-e2.sh calls it after the browser suite finishes. It prints the table and
nothing else — the caveats that make the rows unsummable (the SSO Flow rows'
mixed basis, Authorization management's two nested figures, and the untimed
login setup for Token refresh) are in benchmark/README.md and in each harness's
own header.

A harness that was not run leaves its rows marked "not run" rather than failing
the summary.

The row -> (file, field) mapping below is the authority, but every report also
declares its own mapping in `table4_rows` ("<row> = <field>"). Where a report
declares one, it is checked against this table and a mismatch is reported
rather than silently preferring either side: a spec that changes which column
backs a row would otherwise be summarised under the old meaning.
"""

import argparse
from datetime import datetime
import json
import os
import sys

# Each row of paper Table 4: which report supplies it, and which of that
# report's `stages` entries is the figure. Keep the order of the paper.
#
# Columns: (stage, printed label, label as the report declares it in
# table4_rows, report key, field).
#
# Authorization management is printed as two lines because one number would
# hide something that matters:
#
#   Authorization management  (server) is the IdP's own time; (client) is what
#                             the user waits for in the browser. Nested, not
#                             complementary.
ROWS = [
    ("SSO Flow", 'Click "Login"', 'Click "Login"',
     "login", "click_login_machine_ms"),
    ("SSO Flow", "Consent check", "Consent check",
     "login", "consent_check_ms"),
    ("SSO Flow", "Authorization code exchange", "Authorization code exchange",
     "login", "code_exchange_machine_ms"),
    ("SSO Flow", "Login successful (Total)", "Login successful (Total)",
     "login", "total_ms"),
    ("Extension", "Authorization management (server)", "Authorization management",
     "authz", "authorization_mgmt_ms"),
    ("Extension", "Authorization management (client)", "Authorization management",
     "authz", "client_total_ms"),
    ("Extension", "Token refresh", "Token refresh",
     "refresh", "token_refresh_ms"),
]

# Report key -> (filename stem, which harness produces it).
SOURCES = {
    "login": ("e2-login_latency", "E2 browser/perf/login_latency.spec.ts"),
    "authz": ("e2-authorization_mgmt", "E2 browser/perf/authorization_mgmt.spec.ts"),
    "refresh": ("e2-token_refresh", "E2 browser/perf/token_refresh.spec.ts"),
}



def load(results_dir, profile, key):
    stem, _ = SOURCES[key]
    path = os.path.join(results_dir, f"{stem}-{profile}.json")
    if not os.path.exists(path):
        return None, path
    with open(path, encoding="utf-8") as fh:
        return json.load(fh), path


def declared_mapping(report):
    """Row label -> field, as the report itself declares in table4_rows."""
    out = {}
    for entry in report.get("table4_rows", []):
        if "=" not in entry:
            continue
        row, field = entry.split("=", 1)
        # "total_ms (with interaction)" -> "total_ms"
        out[row.strip()] = field.strip().split()[0]
    return out


def check_mapping(report, group, label, field, warnings):
    declared = declared_mapping(report).get(f"{group} / {label}")
    if declared and declared != field:
        warnings.append(
            f"{group} / {label}: report declares '{declared}', "
            f"summarize.py uses '{field}'"
        )


def fmt(value):
    return "—" if value is None else f"{value:.2f}"


def written(report):
    """When a report was generated, in local time. The two harnesses stamp
    different zones (the browser one UTC, the Go one with an offset), so they
    are normalised rather than string-sliced."""
    raw = report.get("generated_at")
    if not raw:
        return "?"
    try:
        ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return raw
    return ts.astimezone().strftime("%m-%d %H:%M")


def render(rows, markdown):
    head = ["Stage", "Operation", "mean (ms)", "n"]
    if markdown:
        out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
        for r in rows:
            out.append("| " + " | ".join(r) + " |")
        return "\n".join(out)

    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(head)]
    align = "<<>>"

    def line(cells):
        return "  ".join(
            f"{c:{align[i]}{widths[i]}}" for i, c in enumerate(cells)
        ).rstrip()

    out = [line(head), line(["-" * w for w in widths])]
    prev_group = None
    for r in rows:
        # Print the stage name only when it changes, like the paper's table.
        cells = list(r)
        if cells[0] == prev_group:
            cells[0] = ""
        else:
            prev_group = cells[0]
        out.append(line(cells))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Consolidate E2 reports into Table 4.")
    ap.add_argument("--profile", default=os.environ.get("ORION_PROFILE", "demo"))
    ap.add_argument(
        "--results-dir",
        default=os.environ.get(
            "ORION_PERF_OUT",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results"),
        ),
    )
    ap.add_argument("--markdown", action="store_true", help="emit a markdown table")
    ap.add_argument(
        "--components",
        action="store_true",
        help="also print each report's other columns and sub-measures",
    )
    args = ap.parse_args()

    results_dir = os.path.normpath(args.results_dir)
    reports, paths, missing = {}, {}, []
    for key in SOURCES:
        report, path = load(results_dir, args.profile, key)
        paths[key] = path
        if report is None:
            missing.append(key)
        else:
            reports[key] = report

    if not reports:
        print(
            f"no E2 reports for profile '{args.profile}' in {results_dir}\n"
            "run ./benchmark/run-e2.sh first",
            file=sys.stderr,
        )
        return 1

    warnings, table = [], []
    for group, label, declared_label, key, field in ROWS:
        report = reports.get(key)
        if report is None:
            table.append([group, label, "not run", "—"])
            continue
        check_mapping(report, group, declared_label, field, warnings)
        stats = report.get("stages", {}).get(field)
        if stats is None:
            warnings.append(f"{group} / {label}: no '{field}' in {paths[key]}")
            table.append([group, label, "missing", "—"])
            continue
        table.append([
            group, label,
            fmt(stats.get("mean_ms")),
            str(stats.get("n", "—")),
        ])

    print(f"\nOrionLink — paper Table 4 (tab:latency-breakdown), profile={args.profile}")
    # Per-report timestamps, not just iteration counts: the summary reads
    # whatever is in results/, including reports from earlier partial/direct
    # runs. Showing when each was written makes stale combinations visible.
    print("reports: " + "  ".join(
        f"{k} {written(r)}" for k, r in reports.items()
    ))
    print()
    print(render(table, args.markdown))

    if args.components:
        for key, report in reports.items():
            print(f"\n--- {SOURCES[key][1]} ---")
            for block in ("stages", "measures"):
                for name, s in (report.get(block) or {}).items():
                    print(
                        f"  {name:<34} mean {s['mean_ms']:9.2f} ms  "
                        f"p50 {s['p50_ms']:9.2f}  p95 {s['p95_ms']:9.2f}  "
                        f"sd {s['stddev_ms']:.2f}"
                    )

    if missing:
        print("\nnot run (rows above marked accordingly):")
        for key in missing:
            print(f"  {SOURCES[key][1]}  ->  {paths[key]}")

    if warnings:
        print("\nMAPPING WARNINGS — a harness may have changed which column "
              "backs a row:", file=sys.stderr)
        for w in warnings:
            print(f"  {w}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
