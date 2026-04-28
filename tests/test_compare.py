from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from lib.exceptions import apply_exception_rules, load_exception_rules
from lib.loaders import load_bhom_events, load_truesight_events, parse_truesight_baroc
from lib.matching import compare_critical_presence
from lib.models import CanonicalEvent


class LoaderTests(unittest.TestCase):
    def test_truesight_stage_comes_from_prod_category(self) -> None:
        truesight_payload = """PATROL_EV;
\tevent_handle='ts-stage';
\tmc_ueid='ts-stage';
\tmc_host=swppro1;
\tmc_object_class=TKS_OSCMD;
\tmc_object='canonical-instance';
\tmc_parameter=OScoll;
\tprod_category='PRODUCTION';
\tmc_incident_time=1776945829;
\tstatus=OPEN;
\tseverity=CRITICAL;
\tmsg='Disk alert';
END
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            truesight_path = Path(temp_dir) / "truesight.baroc"
            truesight_path.write_text(truesight_payload)

            truesight = load_truesight_events(truesight_path)

        self.assertEqual("PRODUCTION", truesight.events[0].stage)

    def test_truesight_instance_comes_from_mc_object(self) -> None:
        truesight_payload = """PATROL_EV;
\tevent_handle='ts-instance';
\tmc_ueid='ts-instance';
\tmc_host=swppro1;
\tmc_object_class=TKS_OSCMD;
\tmc_object='canonical-instance';
\tp_instance='legacy-instance';
\tmc_parameter=OScoll;
\tmc_incident_time=1776945829;
\tstatus=OPEN;
\tseverity=CRITICAL;
\tmsg='Disk alert';
END
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            truesight_path = Path(temp_dir) / "truesight.baroc"
            truesight_path.write_text(truesight_payload)

            truesight = load_truesight_events(truesight_path)

        self.assertEqual("canonical-instance", truesight.events[0].instance_name)
        self.assertEqual("canonical-instance", truesight.events[0].object_name)

    def test_bhom_instance_comes_from_instancename(self) -> None:
        bhom_payload = {
            "creation_time": 1776945829000,
            "severity": "CRITICAL",
            "status": "OPEN",
            "object_class": "TKS_OSCMD",
            "object": "legacy-object",
            "instancename": "canonical-instance",
            "source_hostname": "swppro1.dmz.six-group.net",
            "_identifier": "bhom-instance",
            "six_notification_group": "4005",
            "msg": "Disk alert",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            bhom_path = Path(temp_dir) / "bhom.json"
            bhom_path.write_text(json.dumps(bhom_payload))

            bhom = load_bhom_events(bhom_path)

        self.assertEqual("canonical-instance", bhom.events[0].instance_name)
        self.assertEqual("canonical-instance", bhom.events[0].object_name)
        self.assertEqual("", bhom.events[0].stage)

    def test_exception_rules_filter_matching_truesight_events(self) -> None:
        exception_csv = """stage,host,object class,instance,parameter,msg
PROD.*,host-a,TKS_OSCMD,instance-a,OScoll,Disk.*
"""
        event = CanonicalEvent(
            "truesight",
            "ts-1",
            datetime(2026, 4, 27, 12, 0, 0, tzinfo=UTC),
            "OPEN",
            "CRITICAL",
            "TKS_OSCMD",
            "instance-a",
            "instance-a",
            "OScoll",
            "",
            "host-a",
            "Disk alert on node",
            "",
            "",
            "",
            "4005",
            "",
            {},
            "PRODUCTION",
        )
        other = CanonicalEvent(
            "truesight",
            "ts-2",
            datetime(2026, 4, 27, 12, 10, 0, tzinfo=UTC),
            "OPEN",
            "CRITICAL",
            "TKS_OSCMD",
            "instance-b",
            "instance-b",
            "OScoll",
            "",
            "host-b",
            "Disk alert on another node",
            "",
            "",
            "",
            "4005",
            "",
            {},
            "TEST",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            exception_path = Path(temp_dir) / "exceptions.csv"
            exception_path.write_text(exception_csv)
            rules = load_exception_rules(exception_path)
            kept, excluded, issues = apply_exception_rules([event, other], rules, path=exception_path)

        self.assertEqual(["ts-2"], [item.event_id for item in kept])
        self.assertEqual(["ts-1"], [item.event_id for item in excluded])
        self.assertEqual("exception_filtered", issues[0]["kind"])
        self.assertEqual(1, issues[0]["excluded_count"])
        self.assertEqual(1, issues[0]["rule_count"])

    def test_exception_rules_can_be_loaded_without_header_row(self) -> None:
        exception_csv = "PROD.*,host-a,TKS_OSCMD,instance-a,OScoll,Disk.*\n"

        with tempfile.TemporaryDirectory() as temp_dir:
            exception_path = Path(temp_dir) / "exceptions.csv"
            exception_path.write_text(exception_csv)
            rules = load_exception_rules(exception_path)

        self.assertEqual(1, len(rules))
        self.assertEqual({"stage", "host", "object_class", "instance_name", "parameter_name", "message"}, set(rules[0].patterns))

    def test_exception_rule_literal_star_behaves_like_wildcard(self) -> None:
        exception_csv = "*,host-a,*,*,*,*\n"

        with tempfile.TemporaryDirectory() as temp_dir:
            exception_path = Path(temp_dir) / "exceptions.csv"
            exception_path.write_text(exception_csv)
            rules = load_exception_rules(exception_path)

        self.assertEqual(".*", rules[0].patterns["stage"].pattern)
        self.assertEqual(".*", rules[0].patterns["object_class"].pattern)
        self.assertEqual(".*", rules[0].patterns["message"].pattern)

    def test_fingerprint_match_is_treated_as_definitive(self) -> None:
        truesight = CanonicalEvent(
            "truesight",
            "ts-fingerprint",
            datetime(2026, 4, 27, 12, 0, 0, tzinfo=UTC),
            "OPEN",
            "CRITICAL",
            "TS_CLASS",
            "ts-object",
            "ts-instance",
            "ts-parameter",
            "ts-metric",
            "ts-host",
            "Truesight alert",
            "",
            "shared-fingerprint",
            "",
            "4005",
            "",
            {},
        )
        bhom = CanonicalEvent(
            "bhom",
            "bh-fingerprint",
            datetime(2026, 4, 27, 12, 45, 0, tzinfo=UTC),
            "OPEN",
            "CRITICAL",
            "BH_CLASS",
            "bh-object",
            "bh-instance",
            "bh-parameter",
            "bh-metric",
            "bh-host",
            "Completely different BHOM alert",
            "",
            "shared-fingerprint",
            "",
            "4999",
            "",
            {},
        )

        result = compare_critical_presence([truesight], [bhom])

        self.assertEqual(1, result["summary"]["matched_count"])
        self.assertEqual("bh-fingerprint", result["matched"][0]["bhom_event"]["event_id"])
        self.assertIn("fingerprint", result["matched"][0]["matched_on"])
        self.assertEqual("high", result["matched"][0]["confidence"])

    def test_full_identity_match_is_treated_as_definitive(self) -> None:
        truesight = CanonicalEvent(
            "truesight",
            "ts-identity",
            datetime(2026, 4, 27, 12, 0, 0, tzinfo=UTC),
            "OPEN",
            "CRITICAL",
            "TKS_OSCMD",
            "BME_LZ_MSG_WATCH",
            "BME_LZ_MSG_WATCH",
            "OScoll",
            "",
            "swppro1",
            "Disk alert",
            "",
            "",
            "",
            "4005",
            "",
            {},
        )
        bhom = CanonicalEvent(
            "bhom",
            "bh-identity",
            datetime(2026, 4, 27, 13, 0, 0, tzinfo=UTC),
            "OPEN",
            "CRITICAL",
            "TKS_OSCMD",
            "BME_LZ_MSG_WATCH",
            "BME_LZ_MSG_WATCH",
            "",
            "OScoll",
            "swppro1.dmz.six-group.net",
            "Different wording",
            "",
            "",
            "",
            "4999",
            "",
            {},
        )

        result = compare_critical_presence([truesight], [bhom])

        self.assertEqual(1, result["summary"]["matched_count"])
        self.assertEqual("bh-identity", result["matched"][0]["bhom_event"]["event_id"])
        self.assertIn("full_identity", result["matched"][0]["matched_on"])
        self.assertEqual("high", result["matched"][0]["confidence"])

    def test_host_time_and_message_similarity_drive_fallback_matching(self) -> None:
        truesight = CanonicalEvent(
            "truesight",
            "ts-fallback",
            datetime(2026, 4, 27, 12, 0, 0, tzinfo=UTC),
            "OPEN",
            "CRITICAL",
            "TRUESIGHT_ONLY",
            "ts-object",
            "ts-instance",
            "",
            "",
            "shared-host",
            "MonitorQueue process is not running on node alpha",
            "",
            "",
            "",
            "4005",
            "",
            {},
        )
        better = CanonicalEvent(
            "bhom",
            "bh-better",
            datetime(2026, 4, 27, 12, 4, 0, tzinfo=UTC),
            "OPEN",
            "CRITICAL",
            "BHOM_ONLY",
            "bh-object-a",
            "bh-instance-a",
            "",
            "",
            "shared-host.domain",
            "MonitorQueue process is not running on node beta",
            "",
            "",
            "",
            "4005",
            "",
            {},
        )
        weaker = CanonicalEvent(
            "bhom",
            "bh-weaker",
            datetime(2026, 4, 27, 12, 50, 0, tzinfo=UTC),
            "OPEN",
            "CRITICAL",
            "BHOM_ONLY",
            "bh-object-b",
            "bh-instance-b",
            "",
            "",
            "shared-host.domain",
            "Filesystem utilization warning on another service",
            "",
            "",
            "",
            "4005",
            "",
            {},
        )

        result = compare_critical_presence([truesight], [better, weaker])

        self.assertEqual(1, result["summary"]["matched_count"])
        self.assertEqual("bh-better", result["matched"][0]["bhom_event"]["event_id"])
        self.assertIn("message_time_fallback", result["matched"][0]["matched_on"])
        self.assertIn("host", result["matched"][0]["matched_on"])
        self.assertGreater(result["matched"][0]["message_similarity"], 0.7)

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
        self.assertGreater(result["matched"][0]["score_breakdown"]["host"], 0)
        self.assertGreater(result["matched"][0]["score_breakdown"]["message_signature"], 0)

    def test_bhom_jsonl_raw_events_are_loaded(self) -> None:
        bhom_payload = """{"creation_time": 1776945829000, "severity": "CRITICAL", "status": "OPEN", "object_class": "TKS_OSCMD", "object": "BME_LZ_MSG_WATCH", "source_hostname": "swppro1.dmz.six-group.net", "_identifier": "bhom-jsonl-1", "six_notification_group": "4005", "msg": "Disk alert"}
{"creation_time": 1776945830000, "severity": "WARNING", "status": "OPEN", "object_class": "TKS_OSCMD", "object": "BME_LZ_MSG_WATCH", "source_hostname": "swppro1.dmz.six-group.net", "_identifier": "bhom-jsonl-2", "six_notification_group": "4005", "msg": "Disk alert"}"""

        with tempfile.TemporaryDirectory() as temp_dir:
            bhom_path = Path(temp_dir) / "bhom.jsonl"
            bhom_path.write_text(bhom_payload)

            bhom = load_bhom_events(bhom_path)

        self.assertEqual("jsonl", bhom.metadata["parser"])
        self.assertEqual(2, bhom.metadata["event_count"])
        self.assertEqual(["bhom-jsonl-1", "bhom-jsonl-2"], [event.event_id for event in bhom.events])

    def test_bhom_jsonl_hits_lines_report_partial_exports(self) -> None:
        bhom_payload = """{"hits": {"total": {"value": 3, "relation": "eq"}, "hits": [{"_source": {"creation_time": 1776945829000, "severity": "CRITICAL", "status": "OPEN", "object_class": "TKS_OSCMD", "object": "BME_LZ_MSG_WATCH", "source_hostname": "swppro1.dmz.six-group.net", "_identifier": "bhom-jsonl-hit-1", "six_notification_group": "4005", "msg": "Disk alert"}}]}}
{"hits": {"total": {"value": 1, "relation": "eq"}, "hits": [{"_source": {"creation_time": 1776945830000, "severity": "WARNING", "status": "OPEN", "object_class": "TKS_OSCMD", "object": "BME_LZ_MSG_WATCH", "source_hostname": "swppro1.dmz.six-group.net", "_identifier": "bhom-jsonl-hit-2", "six_notification_group": "4005", "msg": "Disk alert"}}]}}"""

        with tempfile.TemporaryDirectory() as temp_dir:
            bhom_path = Path(temp_dir) / "bhom.jsonl"
            bhom_path.write_text(bhom_payload)

            bhom = load_bhom_events(bhom_path)

        self.assertEqual("jsonl", bhom.metadata["parser"])
        self.assertEqual(2, bhom.metadata["responses"])
        self.assertEqual(4, bhom.metadata["reported_total"])
        self.assertEqual("partial_export", bhom.issues[0]["kind"])
        self.assertEqual(2, bhom.issues[0]["materialized_hits"])
        self.assertEqual(4, bhom.issues[0]["reported_total"])

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
