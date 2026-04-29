from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lib.reporting import (
    build_browser_payload,
    write_browser_report,
    write_mapping_documentation,
    write_matching_documentation,
    write_statistics_report,
)


class ReportingTests(unittest.TestCase):
    def test_browser_report_contains_expected_sections(self) -> None:
        summary = {
            "truesight": {
                "analyzed_event_count": 12,
                "excluded_critical_event_count": 2,
                "start_time": "2026-04-23T11:00:00Z",
                "end_time": "2026-04-23T12:00:00Z",
            },
            "bhom": {
                "analyzed_event_count": 20,
                "excluded_event_count": 1,
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
            "issues": [
                {"kind": "partial_export", "materialized_hits": 20, "reported_total": 30},
                {"kind": "analysis_window_limited", "start_time": "2026-04-23T11:15:00Z", "end_time": "2026-04-23T11:45:00Z"},
                {"kind": "exception_filtered", "excluded_count": 2, "rule_count": 1, "path": "input/exceptions.csv"},
                {"kind": "bhom_filtered", "excluded_count": 1, "rule_count": 1, "path": "input/bhom-exceptions.csv"},
            ],
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
                        {"event": {"event_id": "bh-3a", "severity": "CRITICAL", "notification_group": "4005"}, "score": 91, "matched_on": ["host", "message_similarity"], "message_similarity": 0.922, "time_delta_seconds": 180},
                        {"event": {"event_id": "bh-3b", "severity": "WARNING", "notification_group": "4999"}, "score": 90, "matched_on": ["host", "message_similarity"], "message_similarity": 0.915, "time_delta_seconds": 240},
                    ],
                    "reason": "Top candidates remain too close to choose safely. bh-3a: score 91, message similarity 0.922, time delta 180s, matched on [host, message_similarity]. bh-3b: score 90, message similarity 0.915, time delta 240s, matched on [host, message_similarity]. Shared signals: host, message_similarity.",
                }
            ],
            "unmatched": [],
            "filtered": [
                {
                    "truesight_event": {
                        "source": "truesight",
                        "event_id": "ts-filtered",
                        "stage": "PRODUCTION",
                        "object_class": "A",
                        "object_name": "objf",
                        "instance_name": "objf",
                        "host": "hostf",
                        "severity": "CRITICAL",
                        "creation_time": "tf",
                        "notification_group": "4005",
                        "message": "filtered message",
                    },
                    "reason": "Excluded by exception rule.",
                }
            ],
        }
        bhom_to_truesight = {
            "filtered": [
                {
                    "bhom_event": {
                        "source": "bhom",
                        "event_id": "bh-filtered",
                        "stage": "",
                        "object_class": "A",
                        "object_name": "objb",
                        "instance_name": "objb",
                        "host": "hostb",
                        "severity": "WARNING",
                        "creation_time": "tb",
                        "notification_group": "4999",
                        "message": "bhom filtered message",
                    },
                    "reason": "Filtered from BHOM candidates.",
                }
            ]
        }

        payload = build_browser_payload(summary=summary, truesight_to_bhom=truesight_to_bhom, bhom_to_truesight=bhom_to_truesight)

        self.assertEqual(
            ["matched", "severity-mismatch", "responsibility-mismatch", "notification-mismatch", "ambiguous", "unmatched", "filtered", "bhom-filtered"],
            [section["id"] for section in payload["sections"]],
        )
        self.assertEqual(2, len(payload["sections"][0]["rows"]))
        self.assertEqual(1, payload["overall_coverage_count"])
        self.assertEqual(1, payload["responsibility_mismatch_count"])
        self.assertEqual(1, payload["notification_mismatch_count"])

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "index.html"
            write_browser_report(report_path, summary=summary, truesight_to_bhom=truesight_to_bhom, bhom_to_truesight=bhom_to_truesight)
            html = report_path.read_text()
            mapping_path = Path(temp_dir) / "mapping_documentation.html"
            write_mapping_documentation(mapping_path, summary={**summary, "bhom_to_truesight": {"unmatched_count": 3}})
            mapping_html = mapping_path.read_text()
            docs_path = Path(temp_dir) / "matching_documentation.html"
            write_matching_documentation(docs_path, summary={**summary, "bhom_to_truesight": {"unmatched_count": 3}})
            docs_html = docs_path.read_text()
            stats_path = Path(temp_dir) / "statistics.html"
            current_snapshot = {
                "run_timestamp": "2026-04-24T11:37:58Z",
                "dataset": {"fingerprint": "dataset-1234abcd"},
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
                {**current_snapshot, "run_timestamp": "2026-04-23T11:37:58Z", "dataset": {"fingerprint": "dataset-5678efgh"}, "coverage": {"pairing_pct": 70.0, "overall_pct": 40.0, "critical_pct": 50.0}},
                current_snapshot,
            ]
            write_statistics_report(stats_path, current_snapshot=current_snapshot, history=history)
            stats_html = stats_path.read_text()

        self.assertIn("Event comparison browser", html)
        self.assertIn("Mapping documentation", html)
        self.assertIn("Matching documentation", html)
        self.assertIn("Truesight analysed", html)
        self.assertIn("Taken into account", html)
        self.assertIn("BHOM analysed", html)
        self.assertIn("Events: 12", html)
        self.assertIn("Events: 20", html)
        self.assertIn("Filtered: 1", html)
        self.assertIn("Start: 2026-04-23 11:00:00 UTC", html)
        self.assertIn("End: 2026-04-23 12:00:00 UTC", html)
        self.assertIn('"score_breakdown"', html)
        self.assertIn('"object": 35', html)
        self.assertIn("score-total", html)
        self.assertNotIn("Total score", html)
        self.assertIn("reason-modal", html)
        self.assertIn('title="Open reason"', html)
        self.assertIn('title="Open details"', html)
        self.assertIn('renderCopyableIdentifier(row.truesight_event_id, "Copy Truesight event ID")', html)
        self.assertIn('row.bhom_event_id ? renderCopyableIdentifier(row.bhom_event_id, "Copy BHOM event ID") : ""', html)
        self.assertIn(">Score<", html)
        self.assertNotIn(">Score / reason<", html)
        self.assertNotIn(">Details<", html)
        self.assertNotIn(">Truesight resp<", html)
        self.assertNotIn(">BHOM resp<", html)
        self.assertNotIn(">Open<", html)
        self.assertIn(">Message<", html)
        self.assertNotIn(">Event<", html)
        self.assertIn("ts-1", html)
        self.assertIn("bh-1", html)
        self.assertIn("bh-3a", html)
        self.assertIn("bh-3b", html)
        self.assertIn("Shared signals: host, message_similarity.", html)
        self.assertIn("Severity mismatch", html)
        self.assertIn("Responsibility mismatch", html)
        self.assertIn("Notification mismatch", html)
        self.assertIn("Truesight severity", html)
        self.assertIn("BHOM severity", html)
        self.assertIn("Truesight responsibility", html)
        self.assertIn("BHOM responsibility", html)
        self.assertIn("Expected notification type", html)
        self.assertIn("BHOM notification type", html)
        self.assertIn("status-indicator", html)
        self.assertIn("comparison-value", html)
        self.assertIn("copy-id-button", html)
        self.assertIn("copyToClipboard", html)
        self.assertIn("bindCopyButtons", html)
        self.assertIn("Only mismatches", html)
        self.assertIn("All lines", html)
        self.assertIn("Overall coverage", html)
        self.assertIn("issue-banner", html)
        self.assertIn("issue-icon", html)
        self.assertIn("BHOM export is partial", html)
        self.assertIn("Analysis was limited to the shared timeframe 2026-04-23 11:15:00 UTC to 2026-04-23 11:45:00 UTC.", html)
        self.assertIn("Truesight exception rules filtered 2 events using 1 rule(s) from input/exceptions.csv.", html)
        self.assertIn("BHOM filter rules excluded 1 events using 1 rule(s) from input/bhom-exceptions.csv.", html)
        self.assertIn("2 filtered", html)
        self.assertIn("10.00%", html)
        self.assertIn("80.00% coverage", html)
        self.assertIn("75.00% coverage", html)
        self.assertIn("87.50% coverage", html)
        self.assertIn('renderIdentifierStack(row.bhom_severity, "Copy BHOM event ID")', html)
        self.assertIn("escapeAttribute(identifier)", html)
        self.assertIn('"responsibility_alignment": "mismatch"', html)
        self.assertIn('"notification_alignment": "mismatch"', html)
        self.assertIn("No BHOM candidate", html)
        self.assertIn("Filtered", html)
        self.assertIn("Excluded by exception rule.", html)
        self.assertIn("ts-filtered", html)
        self.assertIn("bh-filtered", html)
        self.assertIn("Filtered from BHOM candidates.", html)
        self.assertIn("Object class", html)
        self.assertIn("Instance", html)
        self.assertIn("PRODUCTION", html)
        self.assertNotIn(">Object<", html)
        self.assertIn("Search event id, instance, host, message, severity...", html)
        self.assertIn("Matching documentation", docs_html)
        self.assertIn("Candidate collection", docs_html)
        self.assertIn("Mapping documentation", mapping_html)
        self.assertIn("Severity mismatch", mapping_html)
        self.assertIn("Responsibility mismatch", mapping_html)
        self.assertIn("Notification mismatch", mapping_html)
        self.assertIn("six_notification_group", mapping_html)
        self.assertIn("six_notification_type", mapping_html)
        self.assertIn("<code>mc_object</code>", mapping_html)
        self.assertIn("<code>instancename</code>", mapping_html)
        self.assertIn("<code>instance_name</code>", docs_html)
        self.assertIn("exception", docs_html)
        self.assertIn("Analysis was limited to the shared timeframe 2026-04-23 11:15:00 UTC to 2026-04-23 11:45:00 UTC.", docs_html)
        self.assertIn("Statistics", stats_html)
        self.assertIn("Current run", stats_html)
        self.assertIn("Recent runs", stats_html)
        self.assertIn("Runs recorded", stats_html)
        self.assertIn("Average pairing coverage", stats_html)
        self.assertIn("Average overall coverage", stats_html)
        self.assertIn("Mismatches to check", stats_html)
        self.assertIn("50.00%", stats_html)
        self.assertIn("Current dataset", stats_html)
        self.assertIn("dataset-1234abcd", stats_html)
