from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path

from .models import CanonicalEvent


HEADER_MAP = {
    "stage": "stage",
    "severity": "severity",
    "host": "host",
    "object class": "object_class",
    "object_class": "object_class",
    "instance": "instance_name",
    "instance name": "instance_name",
    "instance_name": "instance_name",
    "parameter": "parameter_name",
    "parameter name": "parameter_name",
    "parameter_name": "parameter_name",
    "msg": "message",
    "message": "message",
    "reason": "reason",
    "comment": "reason",
}

REQUIRED_HEADERS = ("stage", "severity", "host", "object_class", "instance_name", "parameter_name", "message")
LEGACY_REQUIRED_HEADERS = ("stage", "host", "object_class", "instance_name", "parameter_name", "message")


@dataclass(frozen=True)
class ExceptionRule:
    line_number: int
    patterns: dict[str, re.Pattern[str]]
    reason: str = ""

    def matches(self, event: CanonicalEvent) -> bool:
        for field_name, pattern in self.patterns.items():
            value = exception_value(event, field_name)
            if not pattern.search(value):
                return False
        return True


def load_exception_rules(path: str | Path) -> list[ExceptionRule]:
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    if not text.strip():
        return []

    dialect = sniff_csv_dialect(text)
    rows = list(csv.reader(text.splitlines(), dialect))
    if not rows:
        return []

    normalized_headers = [normalize_header(field_name) for field_name in rows[0]]
    has_header = all(header in normalized_headers for header in REQUIRED_HEADERS)
    has_legacy_header = all(header in normalized_headers for header in LEGACY_REQUIRED_HEADERS)

    if has_header:
        return parse_headered_rules(file_path, rows)
    if has_legacy_header:
        return parse_headered_rules(file_path, rows)

    recognized_headers = [header for header in normalized_headers if header]
    if recognized_headers:
        missing = [
            header
            for header in REQUIRED_HEADERS
            if header not in normalized_headers and header != "severity"
        ]
        raise ValueError(
            f"Exception file {file_path} is missing required columns: {', '.join(missing)}."
        )

    return parse_headerless_rules(file_path, rows)


def parse_headered_rules(path: Path, rows: list[list[str]]) -> list[ExceptionRule]:
    headers = rows[0]
    rules: list[ExceptionRule] = []
    for offset, values in enumerate(rows[1:], start=2):
        row = {headers[index]: values[index] if index < len(values) else "" for index in range(len(headers))}
        patterns, reason = compile_rule_patterns(path, offset, row.items())
        if patterns:
            rules.append(ExceptionRule(line_number=offset, patterns=patterns, reason=reason))
    return rules


def parse_headerless_rules(path: Path, rows: list[list[str]]) -> list[ExceptionRule]:
    rules: list[ExceptionRule] = []
    for offset, values in enumerate(rows, start=1):
        if len(values) > len(REQUIRED_HEADERS) + 1:
            raise ValueError(
                f"Exception file {path} line {offset} has {len(values)} columns; expected at most {len(REQUIRED_HEADERS) + 1}."
            )
        uses_legacy_layout = len(values) <= len(LEGACY_REQUIRED_HEADERS) + 1
        headers = LEGACY_REQUIRED_HEADERS if uses_legacy_layout else REQUIRED_HEADERS
        row = {
            headers[index]: values[index] if index < len(values) else ""
            for index in range(len(headers))
        }
        if len(values) > len(headers):
            row["reason"] = values[len(headers)]
        patterns, reason = compile_rule_patterns(path, offset, row.items())
        if patterns:
            rules.append(ExceptionRule(line_number=offset, patterns=patterns, reason=reason))
    return rules


def compile_rule_patterns(
    path: Path,
    line_number: int,
    items: object,
) -> tuple[dict[str, re.Pattern[str]], str]:
    patterns: dict[str, re.Pattern[str]] = {}
    reason = ""
    for raw_header, raw_value in items:
        field_name = normalize_header(str(raw_header))
        if not field_name:
            continue
        value = str(raw_value or "").strip()
        if not value:
            continue
        if field_name == "reason":
            reason = value
            continue
        if value == "*":
            value = ".*"
        try:
            patterns[field_name] = re.compile(value)
        except re.error as exc:
            raise ValueError(
                f"Invalid regex in exception file {path} on line {line_number} for {raw_header!r}: {exc}"
            ) from exc
    return patterns, reason


def sniff_csv_dialect(text: str) -> csv.Dialect:
    sample = "\n".join(text.splitlines()[:5])
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        return csv.get_dialect("excel")


def apply_exception_rules(
    events: list[CanonicalEvent],
    rules: list[ExceptionRule],
    *,
    path: str | Path,
) -> tuple[list[CanonicalEvent], list[dict[str, object]], list[dict[str, object]]]:
    return apply_filter_rules(
        events,
        rules,
        path=path,
        source="truesight",
        event_key="truesight_event",
        issue_kind="exception_filtered",
        issue_message="Truesight events were excluded by exception rules.",
        default_reason="Excluded by exception rule.",
    )


def apply_bhom_filter_rules(
    events: list[CanonicalEvent],
    rules: list[ExceptionRule],
    *,
    path: str | Path,
) -> tuple[list[CanonicalEvent], list[dict[str, object]], list[dict[str, object]]]:
    return apply_filter_rules(
        events,
        rules,
        path=path,
        source="bhom",
        event_key="bhom_event",
        issue_kind="bhom_filtered",
        issue_message="BHOM events were excluded by filter rules.",
        default_reason="Excluded by BHOM filter rule.",
    )


def apply_filter_rules(
    events: list[CanonicalEvent],
    rules: list[ExceptionRule],
    *,
    path: str | Path,
    source: str,
    event_key: str,
    issue_kind: str,
    issue_message: str,
    default_reason: str,
) -> tuple[list[CanonicalEvent], list[dict[str, object]], list[dict[str, object]]]:
    if not rules:
        return events, [], []

    kept: list[CanonicalEvent] = []
    excluded: list[dict[str, object]] = []
    for event in events:
        matching_rule = next((rule for rule in rules if rule.matches(event)), None)
        if matching_rule is None:
            kept.append(event)
            continue
        excluded.append(
            {
                event_key: event,
                "reason": matching_rule.reason or default_reason,
                "rule_line_number": matching_rule.line_number,
            }
        )

    issues: list[dict[str, object]] = []
    if excluded:
        issues.append(
            {
                "source": source,
                "kind": issue_kind,
                "message": issue_message,
                "path": str(path),
                "excluded_count": len(excluded),
                "rule_count": len(rules),
            }
        )

    return kept, excluded, issues


def normalize_header(value: str) -> str:
    clean = value.strip().lstrip("\ufeff").lower().replace("_", " ")
    return HEADER_MAP.get(" ".join(clean.split()), "")


def exception_value(event: CanonicalEvent, field_name: str) -> str:
    if field_name == "object_class":
        return event.object_class
    if field_name == "instance_name":
        return event.instance_name
    if field_name == "parameter_name":
        return event.parameter_name or event.metric_name
    if field_name == "message":
        return event.message
    if field_name == "stage":
        return event.stage
    if field_name == "severity":
        return event.severity
    if field_name == "host":
        return event.host
    return ""
