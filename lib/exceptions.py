from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path

from .models import CanonicalEvent


HEADER_MAP = {
    "stage": "stage",
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
}

REQUIRED_HEADERS = ("stage", "host", "object_class", "instance_name", "parameter_name", "message")


@dataclass(frozen=True)
class ExceptionRule:
    line_number: int
    patterns: dict[str, re.Pattern[str]]

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

    if has_header:
        return parse_headered_rules(file_path, rows)

    return parse_headerless_rules(file_path, rows)


def parse_headered_rules(path: Path, rows: list[list[str]]) -> list[ExceptionRule]:
    headers = rows[0]
    rules: list[ExceptionRule] = []
    for offset, values in enumerate(rows[1:], start=2):
        row = {headers[index]: values[index] if index < len(values) else "" for index in range(len(headers))}
        patterns = compile_rule_patterns(path, offset, row.items())
        if patterns:
            rules.append(ExceptionRule(line_number=offset, patterns=patterns))
    return rules


def parse_headerless_rules(path: Path, rows: list[list[str]]) -> list[ExceptionRule]:
    rules: list[ExceptionRule] = []
    for offset, values in enumerate(rows, start=1):
        if len(values) > len(REQUIRED_HEADERS):
            raise ValueError(
                f"Exception file {path} line {offset} has {len(values)} columns; expected at most {len(REQUIRED_HEADERS)}."
            )
        row = {
            REQUIRED_HEADERS[index]: values[index] if index < len(values) else ""
            for index in range(len(REQUIRED_HEADERS))
        }
        patterns = compile_rule_patterns(path, offset, row.items())
        if patterns:
            rules.append(ExceptionRule(line_number=offset, patterns=patterns))
    return rules


def compile_rule_patterns(
    path: Path,
    line_number: int,
    items: object,
) -> dict[str, re.Pattern[str]]:
    patterns: dict[str, re.Pattern[str]] = {}
    for raw_header, raw_value in items:
        field_name = normalize_header(str(raw_header))
        if not field_name:
            continue
        value = str(raw_value or "").strip()
        if not value:
            continue
        if value == "*":
            value = ".*"
        try:
            patterns[field_name] = re.compile(value)
        except re.error as exc:
            raise ValueError(
                f"Invalid regex in exception file {path} on line {line_number} for {raw_header!r}: {exc}"
            ) from exc
    return patterns


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
) -> tuple[list[CanonicalEvent], list[CanonicalEvent], list[dict[str, object]]]:
    if not rules:
        return events, [], []

    kept: list[CanonicalEvent] = []
    excluded: list[CanonicalEvent] = []
    for event in events:
        if any(rule.matches(event) for rule in rules):
            excluded.append(event)
        else:
            kept.append(event)

    issues: list[dict[str, object]] = []
    if excluded:
        issues.append(
            {
                "source": "truesight",
                "kind": "exception_filtered",
                "message": "Truesight events were excluded by exception rules.",
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
    if field_name == "host":
        return event.host
    return ""
