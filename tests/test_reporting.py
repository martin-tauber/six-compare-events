from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lib.reporting import build_browser_payload, write_browser_report, write_matching_documentation


class ReportingTests(unittest.TestCase):
    def test_browser_report_contains_expected_sections(self) -> None:
        summary = {
            "truesight_to_bhom": {
                "critical_events_in_truesight": 10,
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
                    "truesight_event": {"source": "truesight", "event_id": "ts-1", "object_class": "A", "object_name": "obj", "host": "host", "severity": "CRITICAL", "creation_time": "t1", "notification_group": "1", "message": "msg"},
                    "bhom_event": {"source": "bhom", "event_id": "bh-1", "object_class": "A", "object_name": "obj", "host": "host", "severity": "CRITICAL", "creation_time": "t2", "notification_group": "1", "message": "msg"},
                    "confidence": "high",
                    "score": 100,
                    "matched_on": ["object"],
                    "score_breakdown": {"object": 35, "host": 20},
                    "severity_alignment": "critical",
                    "responsibility_alignment": "match",
                    "message_similarity": 1.0,
                    "time_delta_seconds": 0,
                }
            ],
            "matched_to_noncritical": [
                {
                    "truesight_event": {"source": "truesight", "event_id": "ts-2", "object_class": "A", "object_name": "obj2", "host": "host2", "severity": "CRITICAL", "creation_time": "t3", "notification_group": "4005", "message": "msg2"},
                    "bhom_event": {"source": "bhom", "event_id": "bh-2", "object_class": "A", "object_name": "obj2", "host": "host2", "severity": "WARNING", "creation_time": "t4", "notification_group": "4999", "message": "msg2"},
                    "confidence": "medium",
                    "score": 88,
                    "matched_on": ["object"],
                    "score_breakdown": {"object": 35, "host": 20},
                    "severity_alignment": "noncritical",
                    "responsibility_alignment": "mismatch",
                    "message_similarity": 1.0,
                    "time_delta_seconds": 0,
                }
            ],
            "ambiguous": [],
            "unmatched": [],
        }

        payload = build_browser_payload(summary=summary, truesight_to_bhom=truesight_to_bhom)

        self.assertEqual(
            ["matched", "severity-mismatch", "responsibility-mismatch", "ambiguous", "unmatched"],
            [section["id"] for section in payload["sections"]],
        )
        self.assertEqual(1, payload["responsibility_mismatch_count"])

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "index.html"
            write_browser_report(report_path, summary=summary, truesight_to_bhom=truesight_to_bhom)
            html = report_path.read_text()
            docs_path = Path(temp_dir) / "matching_documentation.html"
            write_matching_documentation(docs_path, summary={**summary, "bhom_to_truesight": {"unmatched_count": 3}})
            docs_html = docs_path.read_text()

        self.assertIn("Event comparison browser", html)
        self.assertIn("Matching documentation", html)
        self.assertIn('"score_breakdown"', html)
        self.assertIn('"object": 35', html)
        self.assertIn("Total score", html)
        self.assertIn("Severity mismatch", html)
        self.assertIn("Responsibility mismatch", html)
        self.assertIn('"responsibility_alignment": "mismatch"', html)
        self.assertIn("No BHOM candidate", html)
        self.assertIn("Matching documentation", docs_html)
        self.assertIn("Candidate collection", docs_html)
