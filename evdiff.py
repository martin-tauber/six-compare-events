from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from lib import (
    analyze_critical_events,
    load_bhom_events,
    load_truesight_events,
    write_browser_report,
    write_matching_documentation,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare Truesight and BHOM event dumps and report critical-event coverage."
    )
    parser.add_argument("--truesight", required=True, help="Path to the Truesight BAROC dump")
    parser.add_argument("--bhom", required=True, help="Path to the BHOM dump")
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory where result files should be written",
    )
    args = parser.parse_args()

    truesight = load_truesight_events(args.truesight)
    bhom = load_bhom_events(args.bhom)
    truesight_to_bhom = analyze_critical_events(
        primary_events=truesight.events,
        candidate_events=bhom.events,
        primary_label="truesight",
        candidate_label="bhom",
    )
    bhom_to_truesight = analyze_critical_events(
        primary_events=bhom.events,
        candidate_events=truesight.events,
        primary_label="bhom",
        candidate_label="truesight",
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "truesight": truesight.metadata,
        "bhom": bhom.metadata,
        "truesight_to_bhom": truesight_to_bhom["summary"],
        "bhom_to_truesight": bhom_to_truesight["summary"],
        "issues": truesight.issues + bhom.issues,
    }

    write_json(output_dir / "summary.json", summary)
    write_json(output_dir / "matched_critical_events.json", truesight_to_bhom["matched"])
    write_json(output_dir / "matched_critical_to_critical.json", truesight_to_bhom["matched_to_critical"])
    write_json(output_dir / "matched_critical_to_noncritical.json", truesight_to_bhom["matched_to_noncritical"])
    write_json(output_dir / "unmatched_critical_events.json", truesight_to_bhom["unmatched"])
    write_json(output_dir / "ambiguous_critical_events.json", truesight_to_bhom["ambiguous"])
    write_json(output_dir / "bhom_critical_matches.json", bhom_to_truesight["matched"])
    write_json(output_dir / "bhom_critical_to_truesight_critical.json", bhom_to_truesight["matched_to_critical"])
    write_json(output_dir / "bhom_critical_to_truesight_noncritical.json", bhom_to_truesight["matched_to_noncritical"])
    write_json(output_dir / "bhom_critical_unmatched.json", bhom_to_truesight["unmatched"])
    write_json(output_dir / "bhom_critical_ambiguous.json", bhom_to_truesight["ambiguous"])
    write_json(output_dir / "ingestion_issues.json", truesight.issues + bhom.issues)
    write_browser_report(output_dir / "index.html", summary=summary, truesight_to_bhom=truesight_to_bhom)
    write_matching_documentation(output_dir / "matching_documentation.html", summary=summary)

    write_csv(
        output_dir / "matched_critical_events.csv",
        truesight_to_bhom["matched"],
        [
            "truesight_event_id",
            "bhom_event_id",
            "confidence",
            "score",
            "object_class",
            "object_name",
            "host",
            "truesight_creation_time",
            "bhom_creation_time",
            "truesight_severity",
            "bhom_severity",
            "severity_alignment",
            "truesight_notification_group",
            "bhom_notification_group",
            "responsibility_alignment",
            "matched_on",
        ],
        primary_event_key="truesight_event",
        candidate_event_key="bhom_event",
    )
    write_csv(
        output_dir / "matched_critical_to_noncritical.csv",
        truesight_to_bhom["matched_to_noncritical"],
        [
            "truesight_event_id",
            "bhom_event_id",
            "confidence",
            "score",
            "object_class",
            "object_name",
            "host",
            "truesight_creation_time",
            "bhom_creation_time",
            "truesight_severity",
            "bhom_severity",
            "severity_alignment",
            "truesight_notification_group",
            "bhom_notification_group",
            "responsibility_alignment",
            "matched_on",
        ],
        primary_event_key="truesight_event",
        candidate_event_key="bhom_event",
    )
    write_csv(
        output_dir / "unmatched_critical_events.csv",
        truesight_to_bhom["unmatched"],
        [
            "truesight_event_id",
            "object_class",
            "object_name",
            "host",
            "creation_time",
            "severity",
            "notification_group",
            "reason",
        ],
        primary_event_key="truesight_event",
    )
    write_csv(
        output_dir / "ambiguous_critical_events.csv",
        truesight_to_bhom["ambiguous"],
        [
            "truesight_event_id",
            "object_class",
            "object_name",
            "host",
            "candidate_ids",
            "candidate_scores",
            "reason",
        ],
        primary_event_key="truesight_event",
    )
    write_csv(
        output_dir / "bhom_critical_to_truesight_noncritical.csv",
        bhom_to_truesight["matched_to_noncritical"],
        [
            "bhom_event_id",
            "truesight_event_id",
            "confidence",
            "score",
            "object_class",
            "object_name",
            "host",
            "bhom_creation_time",
            "truesight_creation_time",
            "bhom_severity",
            "truesight_severity",
            "severity_alignment",
            "bhom_notification_group",
            "truesight_notification_group",
            "responsibility_alignment",
            "matched_on",
        ],
        primary_event_key="bhom_event",
        candidate_event_key="truesight_event",
    )
    write_csv(
        output_dir / "bhom_critical_unmatched.csv",
        bhom_to_truesight["unmatched"],
        [
            "bhom_event_id",
            "object_class",
            "object_name",
            "host",
            "creation_time",
            "severity",
            "notification_group",
            "reason",
        ],
        primary_event_key="bhom_event",
    )

    ts_summary = truesight_to_bhom["summary"]
    bhom_summary = bhom_to_truesight["summary"]
    print(f"Truesight critical events: {ts_summary['critical_events_in_truesight']}")
    print(f"Matched to BHOM critical: {ts_summary['matched_to_critical_count']}")
    print(f"Matched to BHOM non-critical: {ts_summary['matched_to_noncritical_count']}")
    print(f"Ambiguous: {ts_summary['ambiguous_count']}")
    print(f"Unmatched: {ts_summary['unmatched_count']}")
    print(f"Pairing coverage: {ts_summary['coverage_pct']}%")
    print(f"Critical coverage: {ts_summary['critical_match_pct']}%")
    print(f"BHOM critical without Truesight critical: {bhom_summary['unmatched_count']}")
    print(f"BHOM critical matched to Truesight non-critical: {bhom_summary['matched_to_noncritical_count']}")
    print(f"Matching documentation: {(output_dir / 'matching_documentation.html').resolve()}")
    print(f"Browser report: {(output_dir / 'index.html').resolve()}")
    print(f"Output directory: {output_dir.resolve()}")


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def write_csv(
    path: Path,
    rows: list[dict[str, object]],
    fieldnames: list[str],
    *,
    primary_event_key: str,
    candidate_event_key: str | None = None,
) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(flatten_row(row, primary_event_key=primary_event_key, candidate_event_key=candidate_event_key))


def flatten_row(
    row: dict[str, object],
    *,
    primary_event_key: str,
    candidate_event_key: str | None = None,
) -> dict[str, object]:
    if candidate_event_key and candidate_event_key in row:
        primary_event = row[primary_event_key]
        candidate_event = row[candidate_event_key]
        primary_prefix = primary_event["source"]
        candidate_prefix = candidate_event["source"]
        return {
            f"{primary_prefix}_event_id": primary_event["event_id"],
            f"{candidate_prefix}_event_id": candidate_event["event_id"],
            "confidence": row["confidence"],
            "score": row["score"],
            "object_class": primary_event["object_class"],
            "object_name": primary_event["object_name"],
            "host": primary_event["host"],
            f"{primary_prefix}_creation_time": primary_event["creation_time"],
            f"{candidate_prefix}_creation_time": candidate_event["creation_time"],
            f"{primary_prefix}_severity": primary_event["severity"],
            f"{candidate_prefix}_severity": candidate_event["severity"],
            "severity_alignment": row["severity_alignment"],
            f"{primary_prefix}_notification_group": primary_event["notification_group"],
            f"{candidate_prefix}_notification_group": candidate_event["notification_group"],
            "responsibility_alignment": row["responsibility_alignment"],
            "matched_on": ",".join(row["matched_on"]),
        }

    if "top_candidates" in row:
        primary_event = row[primary_event_key]
        primary_prefix = primary_event["source"]
        candidates = row["top_candidates"]
        return {
            f"{primary_prefix}_event_id": primary_event["event_id"],
            "object_class": primary_event["object_class"],
            "object_name": primary_event["object_name"],
            "host": primary_event["host"],
            "candidate_ids": ",".join(candidate["event"]["event_id"] for candidate in candidates),
            "candidate_scores": ",".join(str(candidate["score"]) for candidate in candidates),
            "reason": row["reason"],
        }

    primary_event = row[primary_event_key]
    primary_prefix = primary_event["source"]
    return {
        f"{primary_prefix}_event_id": primary_event["event_id"],
        "object_class": primary_event["object_class"],
        "object_name": primary_event["object_name"],
        "host": primary_event["host"],
        "creation_time": primary_event["creation_time"],
        "severity": primary_event["severity"],
        "notification_group": primary_event["notification_group"],
        "reason": row["reason"],
    }


if __name__ == "__main__":
    main()
