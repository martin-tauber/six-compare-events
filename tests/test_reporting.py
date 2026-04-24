from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lib.reporting import (
    build_browser_payload,
    write_browser_report,
    write_matching_documentation,
    write_statistics_report,
)


class ReportingTests(unittest.TestCase):
    def test_browser_report_contains_expected_sections(self) -> None:
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
                "matched_count": 8,
                "matched_to_critical_count": 6,
                "matched_to_noncritical_count": 2,
                "ambiguous_count": 1,
                "unmatched_count": 1,
                "critical_match_pct": 60.0,
            },
            "issues": [],
        }
        truesight_to_bhom = {
            "matched_to_critical": [
                {
                    "truesight_event": {"source": "truesight", "event_id": "ts-1", "object_class": "A", "object_name": "obj", "host": "host", "severity": "CRITICAL", "creation_time": "t1", "notification_group": "1", "notification_type": "ONCALL", "message": "msg"},
                    "bhom_event": {"source": "bhom", "event_id": "bh-1", "object_class": "A", "object_name": "obj", "host": "host", "severity": "CRITICAL", "creation_time": "t2", "notification_group": "1", "notification_type": "ONCALL", "message": "msg"},
                    "confidence": "high",
                    "score": 100,
                    "matched_on": ["object"],
                    "score_breakdown": {"object": 35, "host": 20},
                    "severity_alignment": "critical",
                    "responsibility_alignment": "match",
                    "notification_alignment": "match",
                    "message_similarity": 1.0,
                    "time_delta_seconds": 0,
                }
            ],
            "matched_to_noncritical": [
                {
                    "truesight_event": {"source": "truesight", "event_id": "ts-2", "object_class": "A", "object_name": "obj2", "host": "host2", "severity": "CRITICAL", "creation_time": "t3", "notification_group": "4005", "notification_type": "ONCALL_ITSM", "message": "msg2"},
                    "bhom_event": {"source": "bhom", "event_id": "bh-2", "object_class": "A", "object_name": "obj2", "host": "host2", "severity": "WARNING", "creation_time": "t4", "notification_group": "4999", "notification_type": "ONCALL", "message": "msg2"},
                    "confidence": "medium",
                    "score": 88,
                    "matched_on": ["object"],
                    "score_breakdown": {"object": 35, "host": 20},
                    "severity_alignment": "noncritical",
                    "responsibility_alignment": "mismatch",
                    "notification_alignment": "mismatch",
                    "message_similarity": 1.0,
                    "time_delta_seconds": 0,
                }
            ],
            "ambiguous": [
                {
                    "truesight_event": {"source": "truesight", "event_id": "ts-3", "object_class": "A", "object_name": "obj3", "host": "host3", "severity": "CRITICAL", "creation_time": "t5", "notification_group": "4005", "message": "msg3"},
                    "top_candidates": [
                        {"event": {"event_id": "bh-3a", "severity": "CRITICAL", "notification_group": "4005"}, "score": 91},
                        {"event": {"event_id": "bh-3b", "severity": "WARNING", "notification_group": "4999"}, "score": 90},
                    ],
                    "reason": "Multiple candidates have similarly strong scores.",
                }
            ],
            "unmatched": [],
        }

        payload = build_browser_payload(summary=summary, truesight_to_bhom=truesight_to_bhom)

        self.assertEqual(
            ["matched", "severity-mismatch", "responsibility-mismatch", "notification-mismatch", "ambiguous", "unmatched"],
            [section["id"] for section in payload["sections"]],
        )
        self.assertEqual(1, payload["overall_coverage_count"])
        self.assertEqual(1, payload["responsibility_mismatch_count"])
        self.assertEqual(1, payload["notification_mismatch_count"])

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "index.html"
            write_browser_report(report_path, summary=summary, truesight_to_bhom=truesight_to_bhom)
            html = report_path.read_text()
            docs_path = Path(temp_dir) / "matching_documentation.html"
            write_matching_documentation(docs_path, summary={**summary, "bhom_to_truesight": {"unmatched_count": 3}})
            docs_html = docs_path.read_text()
            stats_path = Path(temp_dir) / "statistics.html"
            current_snapshot = {
                "run_timestamp": "2026-04-24T11:37:58Z",
                "truesight": {
                    "analyzed_event_count": 12,
                    "critical_event_count": 10,
                    "start_time": "2026-04-23T11:00:00Z",
                    "end_time": "2026-04-23T12:00:00Z",
                },
                "bhom": {
                    "analyzed_event_count": 20,
                    "start_time": "2026-04-23T11:00:00Z",
                    "end_time": "2026-04-23T12:00:00Z",
                },
                "coverage": {"pairing_pct": 80.0, "overall_pct": 50.0, "critical_pct": 60.0},
                "truesight_to_bhom": {
                    "matched_count": 8,
                    "mismatch_count": 3,
                    "ambiguous_count": 1,
                    "unmatched_count": 1,
                },
                "bhom_to_truesight": {
                    "critical_events_in_bhom": 15,
                },
            }
            history = [
                {**current_snapshot, "run_timestamp": "2026-04-23T11:37:58Z", "coverage": {"pairing_pct": 70.0, "overall_pct": 40.0, "critical_pct": 50.0}},
                current_snapshot,
            ]
            write_statistics_report(stats_path, current_snapshot=current_snapshot, history=history)
            stats_html = stats_path.read_text()

        self.assertIn("Event comparison browser", html)
        self.assertIn("Matching documentation", html)
        self.assertIn("Truesight analysed", html)
        self.assertIn("BHOM analysed", html)
        self.assertIn("Events: 12", html)
        self.assertIn("Events: 20", html)
        self.assertIn("Start: 2026-04-23 11:00:00 UTC", html)
        self.assertIn("End: 2026-04-23 12:00:00 UTC", html)
        self.assertIn('"score_breakdown"', html)
        self.assertIn('"object": 35', html)
        self.assertIn("score-total", html)
        self.assertNotIn("Total score", html)
        self.assertIn("reason-modal", html)
        self.assertIn('title="Open reason"', html)
        self.assertIn('title="Open details"', html)
        self.assertIn(">Score<", html)
        self.assertNotIn(">Score / reason<", html)
        self.assertNotIn(">Details<", html)
        self.assertNotIn(">Truesight resp<", html)
        self.assertNotIn(">BHOM resp<", html)
        self.assertNotIn(">Open<", html)
        self.assertIn(">Message<", html)
        self.assertNotIn(">Object class<", html)
        self.assertNotIn(">Event<", html)
        self.assertIn("ts-1", html)
        self.assertIn("bh-1", html)
        self.assertIn("bh-3a", html)
        self.assertIn("bh-3b", html)
        self.assertIn("Severity mismatch", html)
        self.assertIn("Responsibility mismatch", html)
        self.assertIn("Notification mismatch", html)
        self.assertIn("Overall coverage", html)
        self.assertIn("10.00%", html)
        self.assertIn("80.00% coverage", html)
        self.assertIn("75.00% coverage", html)
        self.assertIn("87.50% coverage", html)
        self.assertIn('"responsibility_alignment": "mismatch"', html)
        self.assertIn('"notification_alignment": "mismatch"', html)
        self.assertIn("No BHOM candidate", html)
        self.assertIn("Matching documentation", docs_html)
        self.assertIn("Candidate collection", docs_html)
        self.assertIn("Statistics", stats_html)
        self.assertIn("Current run", stats_html)
        self.assertIn("Recent runs", stats_html)
        self.assertIn("Runs recorded", stats_html)
        self.assertIn("Average pairing coverage", stats_html)
        self.assertIn("Average overall coverage", stats_html)
        self.assertIn("Mismatches to check", stats_html)
        self.assertIn("50.00%", stats_html)
