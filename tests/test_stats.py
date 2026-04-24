from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from evdiff import build_stats_snapshot, write_stats_snapshot


class StatsTests(unittest.TestCase):
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
                },
                {
                    "truesight_event": {"event_id": "ts-2"},
                    "severity_alignment": "noncritical",
                    "responsibility_alignment": "mismatch",
                },
                {
                    "truesight_event": {"event_id": "ts-3"},
                    "severity_alignment": "critical",
                    "responsibility_alignment": "mismatch",
                },
                {
                    "truesight_event": {"event_id": "ts-4"},
                    "severity_alignment": "critical",
                    "responsibility_alignment": "match",
                },
            ],
        }
        run_timestamp = datetime(2026, 4, 24, 11, 0, 0, tzinfo=UTC)

        snapshot = build_stats_snapshot(summary, truesight_to_bhom=truesight_to_bhom, run_timestamp=run_timestamp)

        self.assertEqual("2026-04-24T11:00:00Z", snapshot["run_timestamp"])
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

        self.assertEqual(snapshot, latest)
        self.assertEqual(1, len(history_lines))
        self.assertEqual(snapshot["run_timestamp"], json.loads(history_lines[0])["run_timestamp"])
        self.assertEqual(1, len(snapshots))


if __name__ == "__main__":
    unittest.main()
