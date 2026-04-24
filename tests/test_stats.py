from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from evdiff import build_stats_snapshot, limit_events_to_shared_timeframe, write_stats_snapshot
from lib.matching import compare_critical_presence
from lib.models import CanonicalEvent


class StatsTests(unittest.TestCase):
    def test_clamped_primary_events_can_still_match_full_candidate_set(self) -> None:
        truesight_events = [
            CanonicalEvent("truesight", "ts-out", datetime(2026, 4, 23, 11, 0, 0, tzinfo=UTC), "OPEN", "CRITICAL", "CLASS", "other", "other", "", "", "host-a", "ignore", "", "", "", "4005", "", {}),
            CanonicalEvent("truesight", "ts-in", datetime(2026, 4, 23, 11, 30, 0, tzinfo=UTC), "OPEN", "CRITICAL", "CLASS", "object-a", "object-a", "", "", "host-a", "shared message", "", "", "", "4005", "", {}),
        ]
        bhom_events = [
            CanonicalEvent("bhom", "bh-overlap", datetime(2026, 4, 23, 11, 15, 0, tzinfo=UTC), "OPEN", "CRITICAL", "OTHER", "other", "other", "", "", "host-b", "other", "", "", "", "9999", "", {}),
            CanonicalEvent("bhom", "bh-match", datetime(2026, 4, 23, 12, 10, 0, tzinfo=UTC), "OPEN", "CRITICAL", "CLASS", "object-a", "object-a", "", "", "host-a", "shared message", "", "", "", "4005", "", {}),
        ]

        limited_ts, limited_bhom, issues = limit_events_to_shared_timeframe(truesight_events, bhom_events)
        result = compare_critical_presence(limited_ts, bhom_events)

        self.assertEqual(["ts-in"], [event.event_id for event in limited_ts])
        self.assertEqual(["bh-overlap"], [event.event_id for event in limited_bhom])
        self.assertEqual("analysis_window_limited", issues[0]["kind"])
        self.assertEqual(1, result["summary"]["matched_count"])
        self.assertEqual("bh-match", result["matched"][0]["bhom_event"]["event_id"])

    def test_limit_events_to_shared_timeframe_filters_to_overlap_and_reports_issue(self) -> None:
        truesight_events = [
            CanonicalEvent("truesight", "ts-1", datetime(2026, 4, 23, 11, 0, 0, tzinfo=UTC), "", "CRITICAL", "", "", "", "", "", "", "", "", "", "", "", "", {}),
            CanonicalEvent("truesight", "ts-2", datetime(2026, 4, 23, 11, 30, 0, tzinfo=UTC), "", "CRITICAL", "", "", "", "", "", "", "", "", "", "", "", "", {}),
            CanonicalEvent("truesight", "ts-3", datetime(2026, 4, 23, 12, 30, 0, tzinfo=UTC), "", "CRITICAL", "", "", "", "", "", "", "", "", "", "", "", "", {}),
        ]
        bhom_events = [
            CanonicalEvent("bhom", "bh-1", datetime(2026, 4, 23, 11, 15, 0, tzinfo=UTC), "", "CRITICAL", "", "", "", "", "", "", "", "", "", "", "", "", {}),
            CanonicalEvent("bhom", "bh-2", datetime(2026, 4, 23, 12, 0, 0, tzinfo=UTC), "", "CRITICAL", "", "", "", "", "", "", "", "", "", "", "", "", {}),
            CanonicalEvent("bhom", "bh-3", datetime(2026, 4, 23, 12, 45, 0, tzinfo=UTC), "", "CRITICAL", "", "", "", "", "", "", "", "", "", "", "", "", {}),
        ]

        limited_ts, limited_bhom, issues = limit_events_to_shared_timeframe(truesight_events, bhom_events)

        self.assertEqual(["ts-2", "ts-3"], [event.event_id for event in limited_ts])
        self.assertEqual(["bh-1", "bh-2"], [event.event_id for event in limited_bhom])
        self.assertEqual("analysis_window_limited", issues[0]["kind"])
        self.assertEqual("2026-04-23T11:15:00Z", issues[0]["start_time"])
        self.assertEqual("2026-04-23T12:30:00Z", issues[0]["end_time"])

    def test_write_stats_snapshot_creates_latest_history_and_timestamped_file(self) -> None:
        summary = {
            "truesight": {
                "analyzed_event_count": 12,
                "start_time": "2026-04-23T11:00:00Z",
                "end_time": "2026-04-23T12:00:00Z",
            },
            "bhom": {
                "analyzed_event_count": 20,
                "start_time": "2026-04-23T11:00:00Z",
                "end_time": "2026-04-23T12:00:00Z",
            },
            "truesight_to_bhom": {
                "critical_events_in_truesight": 10,
                "coverage_pct": 70.0,
                "critical_match_pct": 60.0,
                "matched_count": 7,
            },
            "bhom_to_truesight": {
                "unmatched_count": 3,
            },
            "issues": [{"kind": "partial_export"}],
        }
        truesight_to_bhom = {
            "summary": summary["truesight_to_bhom"],
            "matched": [
                {
                    "truesight_event": {"event_id": "ts-1"},
                    "severity_alignment": "critical",
                    "responsibility_alignment": "match",
                    "notification_alignment": "match",
                },
                {
                    "truesight_event": {"event_id": "ts-2"},
                    "severity_alignment": "noncritical",
                    "responsibility_alignment": "mismatch",
                    "notification_alignment": "mismatch",
                },
                {
                    "truesight_event": {"event_id": "ts-3"},
                    "severity_alignment": "critical",
                    "responsibility_alignment": "mismatch",
                    "notification_alignment": "match",
                },
                {
                    "truesight_event": {"event_id": "ts-4"},
                    "severity_alignment": "critical",
                    "responsibility_alignment": "match",
                    "notification_alignment": "match",
                },
            ],
        }
        dataset_info = {
            "fingerprint": "dataset-1234abcd",
            "truesight": {"name": "truesight.baroc", "fingerprint": "ts-aaaa", "size_bytes": 123},
            "bhom": {"name": "bhom.json", "fingerprint": "bh-bbbb", "size_bytes": 456},
        }
        run_timestamp = datetime(2026, 4, 24, 11, 0, 0, tzinfo=UTC)

        snapshot = build_stats_snapshot(
            summary,
            truesight_to_bhom=truesight_to_bhom,
            dataset_info=dataset_info,
            run_timestamp=run_timestamp,
        )

        self.assertEqual("2026-04-24T11:00:00Z", snapshot["run_timestamp"])
        self.assertEqual("dataset-1234abcd", snapshot["dataset"]["fingerprint"])
        self.assertEqual(12, snapshot["truesight"]["analyzed_event_count"])
        self.assertEqual(20, snapshot["bhom"]["analyzed_event_count"])
        self.assertEqual(1, snapshot["issue_count"])
        self.assertEqual(2, snapshot["truesight_to_bhom"]["overall_match_count"])
        self.assertEqual(2, snapshot["truesight_to_bhom"]["mismatch_count"])
        self.assertEqual(20.0, snapshot["coverage"]["overall_pct"])

        with tempfile.TemporaryDirectory() as temp_dir:
            stats_dir = Path(temp_dir) / "stats"
            write_stats_snapshot(stats_dir, snapshot)

            latest = json.loads((stats_dir / "latest.json").read_text())
            history_lines = (stats_dir / "history.jsonl").read_text().strip().splitlines()
            snapshots = list(stats_dir.glob("stats_*.json"))
            updated_snapshot = dict(snapshot)
            updated_snapshot["run_timestamp"] = "2026-04-24T12:00:00Z"
            write_stats_snapshot(stats_dir, updated_snapshot)
            updated_history_lines = (stats_dir / "history.jsonl").read_text().strip().splitlines()

        self.assertEqual(snapshot, latest)
        self.assertEqual(1, len(history_lines))
        self.assertEqual(snapshot["run_timestamp"], json.loads(history_lines[0])["run_timestamp"])
        self.assertEqual(1, len(snapshots))
        self.assertEqual(1, len(updated_history_lines))
        self.assertEqual("2026-04-24T12:00:00Z", json.loads(updated_history_lines[0])["run_timestamp"])


if __name__ == "__main__":
    unittest.main()
