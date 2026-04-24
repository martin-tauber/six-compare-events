from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lib.loaders import load_bhom_events, load_truesight_events, parse_truesight_baroc
from lib.matching import compare_critical_presence


class LoaderTests(unittest.TestCase):
    def test_baroc_truesight_parser_recovers_multiline_slots(self) -> None:
        text = """PATROL_EV;
\tevent_handle=58890557;
\tmc_ueid='ts-parse-1';
\tmc_host=swppro1;
\tmc_object_class=TKS_OSCMD;
\tmc_object='BME_LZ_MSG_WATCH';
\tmc_parameter=OScoll;
\tmc_incident_time=1776942229;
\tstatus=OPEN;
\tseverity=CRITICAL;
\tmsg='Broken "quoted" value
/date=Thu Apr 23 11:03:49 2026/
/severity=CRITICAL/.';
\tp_instance='BME_LZ_MSG_WATCH';
\tresp=4005;
\tresp_type=UNDEFINED;
\tmsg_ident='BME_LZ_MSG_WATCH';
END
"""

        events, issues = parse_truesight_baroc(text)

        self.assertEqual(1, len(events))
        self.assertIn('Broken "quoted" value', events[0]["msg"])
        self.assertEqual("BME_LZ_MSG_WATCH", events[0]["msg_ident"])
        self.assertFalse(issues)

    def test_end_to_end_critical_presence_output(self) -> None:
        truesight_payload = """PATROL_EV;
\tevent_handle='ts-1';
\tmc_ueid='ts-ueid-1';
\tmc_host=swppro1;
\tmc_object_class=TKS_OSCMD;
\tmc_object='BME_LZ_MSG_WATCH';
\tmc_parameter=OScoll;
\tmc_incident_time=1776945829;
\tstatus=OPEN;
\tseverity=CRITICAL;
\tmsg='Disk alert';
\tp_instance='BME_LZ_MSG_WATCH';
\tresp=4005;
\tresp_type=UNDEFINED;
\tmsg_ident='BME_LZ_MSG_WATCH';
END
"""
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
            truesight_path = temp_path / "truesight.baroc"
            bhom_path = temp_path / "bhom.json"
            truesight_path.write_text(truesight_payload)
            bhom_path.write_text(json.dumps(bhom_payload))

            truesight = load_truesight_events(truesight_path)
            bhom = load_bhom_events(bhom_path)
            result = compare_critical_presence(truesight.events, bhom.events)

        self.assertEqual(1, result["summary"]["critical_events_in_truesight"])
        self.assertEqual(1, result["summary"]["matched_count"])
        self.assertEqual(0, result["summary"]["unmatched_count"])
        self.assertEqual("ts-ueid-1", result["matched"][0]["truesight_event"]["event_id"])
        self.assertEqual("bhom-1", result["matched"][0]["bhom_event"]["event_id"])
        self.assertEqual("match", result["matched"][0]["responsibility_alignment"])
        self.assertEqual("match", result["matched"][0]["notification_alignment"])
        self.assertIn("score_breakdown", result["matched"][0])
        self.assertGreater(result["matched"][0]["score_breakdown"]["object"], 0)

    def test_truesight_msg_ident_is_extracted_from_message(self) -> None:
        truesight_payload = """PATROL_EV;
\tevent_handle='ts-2';
\tmc_ueid='ts-ueid-2';
\tmc_host=swppro1;
\tmc_object_class=TKS_OSCMD;
\tmc_object='BME_LZ_MSG_WATCH';
\tmc_parameter=OScoll;
\tmc_incident_time=1776942229;
\tstatus=OPEN;
\tseverity=CRITICAL;
\tmsg='BME_LZ_MSG_WATCH /date=Thu Apr 23 11:03:49 2026//severity=CRITICAL//msgident=BME_LZ_MSG_WATCH/.';
\tp_instance='BME_LZ_MSG_WATCH';
\tresp=4005;
\tresp_type=UNDEFINED;
\tmsg_ident='';
END
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            truesight_path = Path(temp_dir) / "truesight.baroc"
            truesight_path.write_text(truesight_payload)

            truesight = load_truesight_events(truesight_path)

        self.assertEqual("BME_LZ_MSG_WATCH", truesight.events[0].msg_ident)
        self.assertTrue(truesight.events[0].fingerprint)

    def test_message_time_fallback_matches_when_keys_do_not_overlap(self) -> None:
        truesight_payload = """PATROL_EV;
\tevent_handle='ts-3';
\tmc_ueid='ts-ueid-3';
\tmc_host='shared-host';
\tmc_object_class='TRUESIGHT_ONLY';
\tmc_object='ts-object';
\tmc_parameter=OScoll;
\tmc_incident_time=1776945829;
\tstatus=OPEN;
\tseverity=CRITICAL;
\tmsg='Unique failure on shared host /date=Thu Apr 23 11:03:49 2026//severity=CRITICAL/.';
\tp_instance='ts-object';
\tresp=4005;
\tresp_type=UNDEFINED;
END
"""
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
            truesight_path = temp_path / "truesight.baroc"
            bhom_path = temp_path / "bhom.json"
            truesight_path.write_text(truesight_payload)
            bhom_path.write_text(json.dumps(bhom_payload))

            truesight = load_truesight_events(truesight_path)
            bhom = load_bhom_events(bhom_path)
            result = compare_critical_presence(truesight.events, bhom.events)

        self.assertEqual(1, result["summary"]["matched_count"])
        self.assertEqual("bhom-2", result["matched"][0]["bhom_event"]["event_id"])
        self.assertIn("message_time_fallback", result["matched"][0]["matched_on"])
        self.assertIn("message_time_fallback", result["matched"][0]["score_breakdown"])

    def test_severity_mismatch_is_classified_separately(self) -> None:
        truesight_payload = """PATROL_EV;
\tevent_handle='ts-4';
\tmc_ueid='ts-ueid-4';
\tmc_host=swppro1;
\tmc_object_class=TKS_OSCMD;
\tmc_object='BME_LZ_MSG_WATCH';
\tmc_parameter=OScoll;
\tmc_incident_time=1776945829;
\tstatus=OPEN;
\tseverity=CRITICAL;
\tmsg='Disk alert';
\tp_instance='BME_LZ_MSG_WATCH';
\tresp=4005;
\tresp_type=UNDEFINED;
\tmsg_ident='BME_LZ_MSG_WATCH';
END
"""
        bhom_payload = {
            "responses": [
                {
                    "hits": {
                        "total": {"value": 1, "relation": "eq"},
                        "hits": [
                            {
                                "_source": {
                                    "creation_time": 1776945829000,
                                    "severity": "OK",
                                    "status": "OPEN",
                                    "object_class": "TKS_OSCMD",
                                    "object": "BME_LZ_MSG_WATCH",
                                    "source_hostname": "swppro1.dmz.six-group.net",
                                    "_identifier": "bhom-3",
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
            truesight_path = temp_path / "truesight.baroc"
            bhom_path = temp_path / "bhom.json"
            truesight_path.write_text(truesight_payload)
            bhom_path.write_text(json.dumps(bhom_payload))

            truesight = load_truesight_events(truesight_path)
            bhom = load_bhom_events(bhom_path)
            result = compare_critical_presence(truesight.events, bhom.events)

        self.assertEqual(1, result["summary"]["matched_count"])
        self.assertEqual(0, result["summary"]["matched_to_critical_count"])
        self.assertEqual(1, result["summary"]["matched_to_noncritical_count"])
        self.assertEqual("noncritical", result["matched"][0]["severity_alignment"])
        self.assertEqual("match", result["matched"][0]["responsibility_alignment"])
        self.assertEqual("match", result["matched"][0]["notification_alignment"])

    def test_responsibility_mismatch_is_exposed_on_match(self) -> None:
        truesight_payload = """PATROL_EV;
\tevent_handle='ts-5';
\tmc_ueid='ts-ueid-5';
\tmc_host=swppro1;
\tmc_object_class=TKS_OSCMD;
\tmc_object='BME_LZ_MSG_WATCH';
\tmc_parameter=OScoll;
\tmc_incident_time=1776945829;
\tstatus=OPEN;
\tseverity=CRITICAL;
\tmsg='Disk alert';
\tp_instance='BME_LZ_MSG_WATCH';
\tresp=4005;
\tresp_type=UNDEFINED;
\tmsg_ident='BME_LZ_MSG_WATCH';
END
"""
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
                                    "_identifier": "bhom-5",
                                    "six_notification_group": "4999",
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
            truesight_path = temp_path / "truesight.baroc"
            bhom_path = temp_path / "bhom.json"
            truesight_path.write_text(truesight_payload)
            bhom_path.write_text(json.dumps(bhom_payload))

            truesight = load_truesight_events(truesight_path)
            bhom = load_bhom_events(bhom_path)
            result = compare_critical_presence(truesight.events, bhom.events)

        self.assertEqual(1, result["summary"]["matched_count"])
        self.assertEqual("mismatch", result["matched"][0]["responsibility_alignment"])
        self.assertEqual("match", result["matched"][0]["notification_alignment"])

    def test_truesight_notification_type_is_derived_from_baroc_slots(self) -> None:
        truesight_payload = """PATROL_EV;
\tevent_handle='ts-6';
\tmc_ueid='ts-ueid-6';
\tmc_host=swppro1;
\tmc_object_class=TKS_OSCMD;
\tmc_object='BME_LZ_MSG_WATCH';
\tmc_parameter=OScoll;
\tmc_incident_time=1776945829;
\tstatus=OPEN;
\tseverity=CRITICAL;
\tmsg='Disk alert';
\tp_instance='BME_LZ_MSG_WATCH';
\tresp=4005;
\talarm_type=AUTO;
\tresp_type=PAGER;
\twith_ars=TRUE;
\tmsg_ident='BME_LZ_MSG_WATCH';
END
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            truesight_path = Path(temp_dir) / "truesight.baroc"
            truesight_path.write_text(truesight_payload)

            truesight = load_truesight_events(truesight_path)

        self.assertEqual("ONCALL_ITSM", truesight.events[0].notification_type)

    def test_notification_mismatch_is_exposed_on_match(self) -> None:
        truesight_payload = """PATROL_EV;
\tevent_handle='ts-7';
\tmc_ueid='ts-ueid-7';
\tmc_host=swppro1;
\tmc_object_class=TKS_OSCMD;
\tmc_object='BME_LZ_MSG_WATCH';
\tmc_parameter=OScoll;
\tmc_incident_time=1776945829;
\tstatus=OPEN;
\tseverity=CRITICAL;
\tmsg='Disk alert';
\tp_instance='BME_LZ_MSG_WATCH';
\tresp=4005;
\talarm_type=AUTO;
\tresp_type=PAGER;
\twith_ars=TRUE;
\tmsg_ident='BME_LZ_MSG_WATCH';
END
"""
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
                                    "_identifier": "bhom-7",
                                    "six_notification_group": "4005",
                                    "six_notification_type": "ONCALL",
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
            truesight_path = temp_path / "truesight.baroc"
            bhom_path = temp_path / "bhom.json"
            truesight_path.write_text(truesight_payload)
            bhom_path.write_text(json.dumps(bhom_payload))

            truesight = load_truesight_events(truesight_path)
            bhom = load_bhom_events(bhom_path)
            result = compare_critical_presence(truesight.events, bhom.events)

        self.assertEqual(1, result["summary"]["matched_count"])
        self.assertEqual("ONCALL_ITSM", result["matched"][0]["truesight_event"]["notification_type"])
        self.assertEqual("ONCALL", result["matched"][0]["bhom_event"]["notification_type"])
        self.assertEqual("mismatch", result["matched"][0]["notification_alignment"])

    def test_notification_undefined_in_bhom_is_treated_as_not_set(self) -> None:
        truesight_payload = """PATROL_EV;
\tevent_handle='ts-8';
\tmc_ueid='ts-ueid-8';
\tmc_host=swppro1;
\tmc_object_class=TKS_OSCMD;
\tmc_object='BME_LZ_MSG_WATCH';
\tmc_parameter=OScoll;
\tmc_incident_time=1776945829;
\tstatus=OPEN;
\tseverity=CRITICAL;
\tmsg='Disk alert';
\tp_instance='BME_LZ_MSG_WATCH';
\tresp=4005;
\talarm_type=MANUAL;
\tresp_type=UNDEFINED;
\twith_ars=UNDEFINED;
\tmsg_ident='BME_LZ_MSG_WATCH';
END
"""
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
                                    "_identifier": "bhom-8",
                                    "six_notification_group": "4005",
                                    "six_notification_type": "UNDEFINED",
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
            truesight_path = temp_path / "truesight.baroc"
            bhom_path = temp_path / "bhom.json"
            truesight_path.write_text(truesight_payload)
            bhom_path.write_text(json.dumps(bhom_payload))

            truesight = load_truesight_events(truesight_path)
            bhom = load_bhom_events(bhom_path)
            result = compare_critical_presence(truesight.events, bhom.events)

        self.assertEqual("", result["matched"][0]["truesight_event"]["notification_type"])
        self.assertEqual("UNDEFINED", result["matched"][0]["bhom_event"]["notification_type"])
        self.assertEqual("match", result["matched"][0]["notification_alignment"])


if __name__ == "__main__":
    unittest.main()
