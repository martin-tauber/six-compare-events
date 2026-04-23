from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from event_compare import compare_critical_presence, load_bhom_events, load_truesight_events


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare Truesight and BHOM event dumps and report critical-event coverage."
    )
    parser.add_argument("--truesight", required=True, help="Path to the Truesight dump")
    parser.add_argument("--bhom", required=True, help="Path to the BHOM dump")
    parser.add_argument(
        "--output-dir",
        default="comparison_output",
        help="Directory where result files should be written",
    )
    args = parser.parse_args()

    truesight = load_truesight_events(args.truesight)
    bhom = load_bhom_events(args.bhom)
    comparison = compare_critical_presence(truesight.events, bhom.events)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "truesight": truesight.metadata,
        "bhom": bhom.metadata,
        "comparison": comparison["summary"],
        "issues": truesight.issues + bhom.issues,
    }

    write_json(output_dir / "summary.json", summary)
    write_json(output_dir / "matched_critical_events.json", comparison["matched"])
    write_json(output_dir / "unmatched_critical_events.json", comparison["unmatched"])
    write_json(output_dir / "ambiguous_critical_events.json", comparison["ambiguous"])
    write_json(output_dir / "ingestion_issues.json", truesight.issues + bhom.issues)

    write_csv(
        output_dir / "matched_critical_events.csv",
        comparison["matched"],
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
            "notification_group",
            "matched_on",
        ],
    )
    write_csv(
        output_dir / "unmatched_critical_events.csv",
        comparison["unmatched"],
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
    )
    write_csv(
        output_dir / "ambiguous_critical_events.csv",
        comparison["ambiguous"],
        [
            "truesight_event_id",
            "object_class",
            "object_name",
            "host",
            "candidate_ids",
            "candidate_scores",
            "reason",
        ],
    )

    summary_metrics = comparison["summary"]
    print(f"Truesight critical events: {summary_metrics['critical_events_in_truesight']}")
    print(f"Matched: {summary_metrics['matched_count']}")
    print(f"Ambiguous: {summary_metrics['ambiguous_count']}")
    print(f"Unmatched: {summary_metrics['unmatched_count']}")
    print(f"Coverage: {summary_metrics['coverage_pct']}%")
    print(f"Output directory: {output_dir.resolve()}")


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(flatten_row(row))


def flatten_row(row: dict[str, object]) -> dict[str, object]:
    if "bhom_event" in row:
        truesight_event = row["truesight_event"]
        bhom_event = row["bhom_event"]
        return {
            "truesight_event_id": truesight_event["event_id"],
            "bhom_event_id": bhom_event["event_id"],
            "confidence": row["confidence"],
            "score": row["score"],
            "object_class": truesight_event["object_class"],
            "object_name": truesight_event["object_name"],
            "host": truesight_event["host"],
            "truesight_creation_time": truesight_event["creation_time"],
            "bhom_creation_time": bhom_event["creation_time"],
            "truesight_severity": truesight_event["severity"],
            "bhom_severity": bhom_event["severity"],
            "notification_group": truesight_event["notification_group"],
            "matched_on": ",".join(row["matched_on"]),
        }

    if "top_candidates" in row:
        truesight_event = row["truesight_event"]
        candidates = row["top_candidates"]
        return {
            "truesight_event_id": truesight_event["event_id"],
            "object_class": truesight_event["object_class"],
            "object_name": truesight_event["object_name"],
            "host": truesight_event["host"],
            "candidate_ids": ",".join(candidate["event"]["event_id"] for candidate in candidates),
            "candidate_scores": ",".join(str(candidate["score"]) for candidate in candidates),
            "reason": row["reason"],
        }

    truesight_event = row["truesight_event"]
    return {
        "truesight_event_id": truesight_event["event_id"],
        "object_class": truesight_event["object_class"],
        "object_name": truesight_event["object_name"],
        "host": truesight_event["host"],
        "creation_time": truesight_event["creation_time"],
        "severity": truesight_event["severity"],
        "notification_group": truesight_event["notification_group"],
        "reason": row["reason"],
    }


if __name__ == "__main__":
    main()
