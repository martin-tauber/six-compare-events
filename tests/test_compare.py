from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from event_compare.loaders import load_bhom_events, load_truesight_events, parse_truesight_loose
from event_compare.matching import compare_critical_presence


class LoaderTests(unittest.TestCase):
    def test_loose_truesight_parser_recovers_invalid_string_values(self) -> None:
        text = """[
{
"creation_time": "2026-04-23 11:03:49",
"severity": "CRITICAL",
"object_class": "TKS_OSCMD",
"object": "BME_LZ_MSG_WATCH",
"source_hostname": "swppro1",
"_identifier": "58890557",
"msg": "Broken "quoted" value"
}
]"""

        events, issues = parse_truesight_loose(text)

        self.assertEqual(1, len(events))
        self.assertEqual('Broken "quoted" value', events[0]["msg"])
        self.assertTrue(issues)

    def test_end_to_end_critical_presence_output(self) -> None:
        truesight_payload = """[
{
"creation_time": "2026-04-23 11:03:49",
"severity": "CRITICAL",
"status": "OPEN",
"object_class": "TKS_OSCMD",
"object": "BME_LZ_MSG_WATCH",
"source_hostname": "swppro1",
"_identifier": "ts-1",
"six_notification_group": "4005",
"six_notification_type": "NONE",
"msg": "Disk alert"
}
]"""
        bhom_payload = {
            "responses": [
                {
                    "hits": {
                        "total": {"value": 1, "relation": "eq"},
                        "hits": [
                            {
                                "_source": {
                                    "creation_time": 1776945829000,
                                    "severity": "CRITICAL",
                                    "status": "OPEN",
                                    "object_class": "TKS_OSCMD",
                                    "object": "BME_LZ_MSG_WATCH",
                                    "source_hostname": "swppro1.dmz.six-group.net",
                                    "_identifier": "bhom-1",
                                    "six_notification_group": "4005",
                                    "msg": "Disk alert",
                                }
                            }
                        ],
                    }
                }
            ]
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            truesight_path = temp_path / "truesight.json"
            bhom_path = temp_path / "bhom.json"
            truesight_path.write_text(truesight_payload)
            bhom_path.write_text(json.dumps(bhom_payload))

            truesight = load_truesight_events(truesight_path)
            bhom = load_bhom_events(bhom_path)
            result = compare_critical_presence(truesight.events, bhom.events)

        self.assertEqual(1, result["summary"]["critical_events_in_truesight"])
        self.assertEqual(1, result["summary"]["matched_count"])
        self.assertEqual(0, result["summary"]["unmatched_count"])
        self.assertEqual("bhom-1", result["matched"][0]["bhom_event"]["event_id"])

    def test_truesight_msg_ident_is_extracted_from_message(self) -> None:
        truesight_payload = """[
{
"creation_time": "2026-04-23 11:03:49",
"severity": "CRITICAL",
"status": "OPEN",
"object_class": "TKS_OSCMD",
"object": "BME_LZ_MSG_WATCH",
"source_hostname": "swppro1",
"_identifier": "ts-2",
"six_notification_group": "4005",
"six_notification_type": "NONE",
"msg": "BME_LZ_MSG_WATCH /date=Thu Apr 23 11:03:49 2026//severity=CRITICAL//msgident=BME_LZ_MSG_WATCH/."
}
]"""

        with tempfile.TemporaryDirectory() as temp_dir:
            truesight_path = Path(temp_dir) / "truesight.json"
            truesight_path.write_text(truesight_payload)

            truesight = load_truesight_events(truesight_path)

        self.assertEqual("BME_LZ_MSG_WATCH", truesight.events[0].msg_ident)
        self.assertTrue(truesight.events[0].fingerprint)

    def test_message_time_fallback_matches_when_keys_do_not_overlap(self) -> None:
        truesight_payload = """[
{
"creation_time": "2026-04-23 11:03:49",
"severity": "CRITICAL",
"status": "OPEN",
"object_class": "TRUESIGHT_ONLY",
"object": "ts-object",
"source_hostname": "shared-host",
"_identifier": "ts-3",
"six_notification_group": "4005",
"six_notification_type": "NONE",
"msg": "Unique failure on shared host /date=Thu Apr 23 11:03:49 2026//severity=CRITICAL/."
}
]"""
        bhom_payload = {
            "responses": [
                {
                    "hits": {
                        "total": {"value": 1, "relation": "eq"},
                        "hits": [
                            {
                                "_source": {
                                    "creation_time": 1776942629000,
                                    "severity": "CRITICAL",
                                    "status": "OPEN",
                                    "object_class": "BHOM_ONLY",
                                    "object": "bhom-object",
                                    "source_hostname": "shared-host.domain",
                                    "_identifier": "bhom-2",
                                    "six_notification_group": "9999",
                                    "msg": "Unique failure on shared host /date=Thu Apr 23 09:10:29 2026//severity=CRITICAL/.",
                                }
                            }
                        ],
                    }
                }
            ]
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            truesight_path = temp_path / "truesight.json"
            bhom_path = temp_path / "bhom.json"
            truesight_path.write_text(truesight_payload)
            bhom_path.write_text(json.dumps(bhom_payload))

            truesight = load_truesight_events(truesight_path)
            bhom = load_bhom_events(bhom_path)
            result = compare_critical_presence(truesight.events, bhom.events)

        self.assertEqual(1, result["summary"]["matched_count"])
        self.assertEqual("bhom-2", result["matched"][0]["bhom_event"]["event_id"])
        self.assertIn("message_time_fallback", result["matched"][0]["matched_on"])


if __name__ == "__main__":
    unittest.main()
