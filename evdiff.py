from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from lib import (
    analyze_critical_events,
    load_bhom_events,
    load_truesight_events,
    write_browser_report,
    write_matching_documentation,
    write_statistics_report,
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
    run_timestamp = datetime.now(UTC)
    dataset_info = build_dataset_info(Path(args.truesight), Path(args.bhom))

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
        "truesight": enrich_source_metadata(truesight.metadata, truesight.events),
        "bhom": enrich_source_metadata(bhom.metadata, bhom.events),
        "truesight_to_bhom": truesight_to_bhom["summary"],
        "bhom_to_truesight": bhom_to_truesight["summary"],
        "issues": truesight.issues + bhom.issues,
    }
    stats_snapshot = build_stats_snapshot(
        summary,
        truesight_to_bhom=truesight_to_bhom,
        dataset_info=dataset_info,
        run_timestamp=run_timestamp,
    )

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
    stats_dir = Path("stats")
    write_stats_snapshot(stats_dir, stats_snapshot)
    write_statistics_report(
        output_dir / "statistics.html",
        current_snapshot=stats_snapshot,
        history=load_stats_history(stats_dir / "history.jsonl"),
    )

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
            "truesight_notification_type",
            "bhom_notification_type",
            "notification_alignment",
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
            "truesight_notification_type",
            "bhom_notification_type",
            "notification_alignment",
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
            "bhom_notification_type",
            "truesight_notification_type",
            "notification_alignment",
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
    print(f"Overall coverage: {stats_snapshot['coverage']['overall_pct']}%")
    print(f"BHOM critical without Truesight critical: {bhom_summary['unmatched_count']}")
    print(f"BHOM critical matched to Truesight non-critical: {bhom_summary['matched_to_noncritical_count']}")
    print(f"Matching documentation: {(output_dir / 'matching_documentation.html').resolve()}")
    print(f"Browser report: {(output_dir / 'index.html').resolve()}")
    print(f"Output directory: {output_dir.resolve()}")


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def append_jsonl(path: Path, payload: object) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True))
        handle.write("\n")


def enrich_source_metadata(metadata: dict[str, object], events: list[object]) -> dict[str, object]:
    creation_times = sorted(
        event.creation_time
        for event in events
        if getattr(event, "creation_time", None) is not None
    )
    enriched = dict(metadata)
    enriched["analyzed_event_count"] = metadata.get("event_count", len(events))
    enriched["start_time"] = format_timestamp(creation_times[0]) if creation_times else ""
    enriched["end_time"] = format_timestamp(creation_times[-1]) if creation_times else ""
    return enriched


def format_timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def build_stats_snapshot(
    summary: dict[str, object],
    *,
    truesight_to_bhom: dict[str, object],
    dataset_info: dict[str, object],
    run_timestamp: datetime,
) -> dict[str, object]:
    truesight = dict(summary["truesight"])
    bhom = dict(summary["bhom"])
    truesight_to_bhom_summary = dict(summary["truesight_to_bhom"])
    bhom_to_truesight = dict(summary["bhom_to_truesight"])
    issues = list(summary.get("issues", []))
    overall_coverage = calculate_overall_coverage(truesight_to_bhom)

    return {
        "run_timestamp": format_timestamp(run_timestamp),
        "dataset": dataset_info,
        "truesight": {
            "analyzed_event_count": truesight.get("analyzed_event_count"),
            "start_time": truesight.get("start_time", ""),
            "end_time": truesight.get("end_time", ""),
            "critical_event_count": truesight_to_bhom_summary.get("critical_events_in_truesight"),
        },
        "bhom": {
            "analyzed_event_count": bhom.get("analyzed_event_count"),
            "start_time": bhom.get("start_time", ""),
            "end_time": bhom.get("end_time", ""),
        },
        "coverage": {
            "pairing_pct": truesight_to_bhom_summary.get("coverage_pct"),
            "overall_pct": overall_coverage["overall_pct"],
            "critical_pct": truesight_to_bhom_summary.get("critical_match_pct"),
        },
        "truesight_to_bhom": {
            **truesight_to_bhom_summary,
            "overall_match_count": overall_coverage["overall_match_count"],
            "mismatch_count": overall_coverage["mismatch_count"],
        },
        "bhom_to_truesight": bhom_to_truesight,
        "issue_count": len(issues),
    }


def calculate_overall_coverage(truesight_to_bhom: dict[str, object]) -> dict[str, object]:
    matched_rows = list(truesight_to_bhom.get("matched", []))
    critical_total = int(dict(truesight_to_bhom.get("summary", {})).get("critical_events_in_truesight", 0) or 0)
    mismatch_ids = {
        str(dict(row.get("truesight_event", {})).get("event_id", ""))
        for row in matched_rows
        if row.get("severity_alignment") != "critical"
        or row.get("responsibility_alignment") != "match"
        or row.get("notification_alignment") != "match"
    }
    mismatch_ids.discard("")
    mismatch_count = len(mismatch_ids)
    overall_match_count = max(len(matched_rows) - mismatch_count, 0)
    overall_pct = round((overall_match_count / critical_total * 100), 2) if critical_total else 0.0
    return {
        "overall_match_count": overall_match_count,
        "mismatch_count": mismatch_count,
        "overall_pct": overall_pct,
    }


def write_stats_snapshot(stats_dir: Path, snapshot: dict[str, object]) -> None:
    stats_dir.mkdir(parents=True, exist_ok=True)
    dataset_fingerprint = str(dict(snapshot.get("dataset", {})).get("fingerprint") or "unknown")
    write_json(stats_dir / "latest.json", snapshot)
    write_json(stats_dir / f"stats_{dataset_fingerprint}.json", snapshot)
    write_history_jsonl(stats_dir / "history.jsonl", snapshot)


def load_stats_history(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def build_dataset_info(truesight_path: Path, bhom_path: Path) -> dict[str, object]:
    truesight_info = fingerprint_file(truesight_path)
    bhom_info = fingerprint_file(bhom_path)
    digest = hashlib.sha256()
    digest.update(b"truesight:")
    digest.update(str(truesight_info["fingerprint"]).encode("utf-8"))
    digest.update(b"|bhom:")
    digest.update(str(bhom_info["fingerprint"]).encode("utf-8"))
    return {
        "fingerprint": digest.hexdigest()[:16],
        "truesight": truesight_info,
        "bhom": bhom_info,
    }


def fingerprint_file(path: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "path": str(path),
        "name": path.name,
        "fingerprint": digest.hexdigest()[:16],
        "size_bytes": path.stat().st_size,
    }


def write_history_jsonl(path: Path, snapshot: dict[str, object]) -> None:
    history = load_stats_history(path)
    dataset_fingerprint = str(dict(snapshot.get("dataset", {})).get("fingerprint") or "")
    replaced = False
    for index, item in enumerate(history):
        item_fingerprint = str(dict(item.get("dataset", {})).get("fingerprint") or "")
        if dataset_fingerprint and item_fingerprint == dataset_fingerprint:
            history[index] = snapshot
            replaced = True
            break
    if not replaced:
        history.append(snapshot)
    path.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in history),
        encoding="utf-8",
    )


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
            f"{primary_prefix}_notification_type": primary_event["notification_type"],
            f"{candidate_prefix}_notification_type": candidate_event["notification_type"],
            "notification_alignment": row["notification_alignment"],
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
