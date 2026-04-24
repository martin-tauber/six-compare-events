from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import CanonicalEvent, LoadResult


def load_truesight_events(path: str | Path) -> LoadResult:
    file_path = Path(path)
    text = file_path.read_text()
    issues: list[dict[str, Any]]

    if file_path.suffix.lower() == ".baroc":
        raw_events, issues = parse_truesight_baroc(text)
        metadata = {
            "path": str(file_path),
            "parser": "baroc",
            "event_count": len(raw_events),
        }
    else:
        issues = []
        try:
            raw_events = json.loads(text)
            metadata = {
                "path": str(file_path),
                "parser": "json",
                "event_count": len(raw_events),
            }
        except json.JSONDecodeError as exc:
            issues.append(
                {
                    "source": "truesight",
                    "kind": "invalid_json",
                    "message": str(exc),
                    "line": exc.lineno,
                    "column": exc.colno,
                }
            )
            raw_events, recovered_issues = parse_truesight_loose(text)
            issues.extend(recovered_issues)
            metadata = {
                "path": str(file_path),
                "parser": "line_recovery",
                "event_count": len(raw_events),
            }

    events = [normalize_truesight_event(event) for event in raw_events]
    return LoadResult(source="truesight", events=events, issues=issues, metadata=metadata)


def load_bhom_events(path: str | Path) -> LoadResult:
    file_path = Path(path)
    with file_path.open() as handle:
        payload = json.load(handle)

    responses = payload.get("responses", [])
    raw_events: list[dict[str, Any]] = []
    reported_total = 0

    for response in responses:
        hits = response.get("hits", {})
        total = hits.get("total", {})
        if isinstance(total, dict):
            reported_total += int(total.get("value", 0) or 0)
        raw_events.extend(hit.get("_source", {}) for hit in hits.get("hits", []))

    issues: list[dict[str, Any]] = []
    if reported_total and reported_total != len(raw_events):
        issues.append(
            {
                "source": "bhom",
                "kind": "partial_export",
                "message": "Export contains fewer materialized hits than the reported total.",
                "reported_total": reported_total,
                "materialized_hits": len(raw_events),
            }
        )

    events = [normalize_bhom_event(event) for event in raw_events]
    metadata = {
        "path": str(file_path),
        "responses": len(responses),
        "event_count": len(events),
        "reported_total": reported_total,
    }
    return LoadResult(source="bhom", events=events, issues=issues, metadata=metadata)


def parse_truesight_loose(text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    inside_object = False
    current_lines: list[str] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped == "{":
            inside_object = True
            current_lines = []
            continue
        if not inside_object:
            continue
        if stripped in ("}", "},"):
            event, field_issues = parse_truesight_object(current_lines, start_line=line_number - len(current_lines))
            events.append(event)
            issues.extend(field_issues)
            inside_object = False
            current_lines = []
            continue
        current_lines.append(line)

    if inside_object and current_lines:
        event, field_issues = parse_truesight_object(current_lines, start_line=0)
        events.append(event)
        issues.extend(field_issues)
        issues.append(
            {
                "source": "truesight",
                "kind": "unterminated_object",
                "message": "Reached end of file while recovering object.",
            }
        )

    return events, issues


def parse_truesight_baroc(text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []

    current_event_type = ""
    current_lines: list[tuple[int, str]] = []
    start_line = 0

    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        event_start = re.match(r"^([A-Z_][A-Z0-9_]*);$", stripped)

        if not current_event_type:
            if event_start:
                current_event_type = event_start.group(1)
                current_lines = []
                start_line = line_number
            continue

        if stripped == "END":
            event, event_issues = parse_truesight_baroc_event(current_event_type, current_lines, start_line)
            events.append(event)
            issues.extend(event_issues)
            current_event_type = ""
            current_lines = []
            start_line = 0
            continue

        current_lines.append((line_number, line))

    if current_event_type:
        event, event_issues = parse_truesight_baroc_event(current_event_type, current_lines, start_line)
        events.append(event)
        issues.extend(event_issues)
        issues.append(
            {
                "source": "truesight",
                "kind": "unterminated_baroc_event",
                "message": "Reached end of file before END marker.",
                "event_type": current_event_type,
                "line": start_line,
            }
        )

    return events, issues


def parse_truesight_baroc_event(
    event_type: str,
    lines: list[tuple[int, str]],
    start_line: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    event: dict[str, Any] = {"event_type": event_type}
    issues: list[dict[str, Any]] = []
    buffer: list[tuple[int, str]] = []
    in_quote = False
    bracket_depth = 0

    for line_number, line in lines:
        buffer.append((line_number, line))
        in_quote, bracket_depth, statement_complete = update_baroc_state(line, in_quote, bracket_depth)
        if not statement_complete:
            continue

        statement = "\n".join(part for _, part in buffer).strip()
        buffer = []
        if statement.endswith(";"):
            statement = statement[:-1]
        if not statement:
            continue

        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", statement, flags=re.DOTALL)
        if not match:
            issues.append(
                {
                    "source": "truesight",
                    "kind": "unparsed_baroc_statement",
                    "message": "Skipped BAROC statement during parsing.",
                    "line": line_number,
                    "content": statement[:240],
                }
            )
            continue

        key, raw_value = match.groups()
        event[key] = parse_baroc_value(raw_value.strip())

    if buffer:
        issues.append(
            {
                "source": "truesight",
                "kind": "unfinished_baroc_statement",
                "message": "BAROC statement did not terminate with semicolon.",
                "line": buffer[0][0] if buffer else start_line,
            }
        )

    return event, issues


def parse_truesight_object(lines: list[str], start_line: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    event: dict[str, Any] = {}
    issues: list[dict[str, Any]] = []

    for offset, raw_line in enumerate(lines):
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.endswith(","):
            stripped = stripped[:-1]

        match = re.match(r'^"([^"]+)":\s*(.*)$', stripped)
        if not match:
            issues.append(
                {
                    "source": "truesight",
                    "kind": "unparsed_field",
                    "message": "Skipped line during loose parsing.",
                    "line": start_line + offset,
                    "content": raw_line.strip(),
                }
            )
            continue

        key, raw_value = match.groups()
        try:
            event[key] = json.loads(raw_value)
            continue
        except json.JSONDecodeError:
            recovered_value = recover_string_value(raw_value)
            event[key] = recovered_value
            issues.append(
                {
                    "source": "truesight",
                    "kind": "recovered_field",
                    "field": key,
                    "line": start_line + offset,
                    "message": "Recovered field with loose string parsing.",
                }
            )

    return event, issues


def recover_string_value(raw_value: str) -> str:
    text = raw_value.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]

    text = text.replace(r"\\", "\\")
    text = text.replace(r"\"", '"')
    text = text.replace(r"\n", "\n")
    text = text.replace(r"\t", "\t")
    return text


def update_baroc_state(line: str, in_quote: bool, bracket_depth: int) -> tuple[bool, int, bool]:
    statement_complete = False
    index = 0

    while index < len(line):
        char = line[index]

        if in_quote:
            if char == "'" and index + 1 < len(line) and line[index + 1] == "'":
                index += 2
                continue
            if char == "'":
                in_quote = False
        else:
            if char == "'":
                in_quote = True
            elif char == "[":
                bracket_depth += 1
            elif char == "]" and bracket_depth > 0:
                bracket_depth -= 1
            elif char == ";" and bracket_depth == 0:
                statement_complete = True

        index += 1

    return in_quote, bracket_depth, statement_complete


def parse_baroc_value(raw_value: str) -> Any:
    text = raw_value.strip()
    if text == "":
        return ""
    if text.startswith("'") and text.endswith("'"):
        return text[1:-1].replace("''", "'")
    if text.startswith("[") and text.endswith("]"):
        return text
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    return text


def normalize_truesight_event(raw: dict[str, Any]) -> CanonicalEvent:
    notes = []
    creation_time = parse_timestamp(raw.get("mc_incident_time") or raw.get("date_reception") or raw.get("date"))
    if creation_time is None and (raw.get("mc_incident_time") or raw.get("date_reception") or raw.get("date")):
        notes.append("unparsed_creation_time")
    object_name = stringify(raw.get("mc_object") or raw.get("object"))
    message = stringify(raw.get("msg"))
    metric_name = extract_metric_name(message)
    instance_name = stringify(raw.get("p_instance") or raw.get("instancename")) or extract_instance_hint(message) or object_name
    parameter_name = stringify(raw.get("mc_parameter") or raw.get("p_parameter")) or extract_parameter_hint(message)
    msg_ident = stringify(raw.get("msg_ident")) or extract_msg_ident(message)
    host = stringify(raw.get("mc_host") or raw.get("six_host") or raw.get("p_node") or raw.get("source_hostname"))
    object_class = stringify(raw.get("mc_object_class") or raw.get("object_class") or raw.get("event_type"))
    source_identifier = stringify(raw.get("p_origin") or raw.get("mc_ueid"))
    fingerprint = build_fingerprint(
        host=host,
        object_class=object_class,
        object_name=object_name,
        instance_name=instance_name,
        parameter_name=parameter_name,
        metric_name=metric_name,
        msg_ident=msg_ident,
    )

    return CanonicalEvent(
        source="truesight",
        event_id=stringify(raw.get("event_handle") or raw.get("_identifier") or raw.get("mc_ueid")),
        creation_time=creation_time,
        status=stringify(raw.get("status")).upper(),
        severity=stringify(raw.get("severity")).upper(),
        object_class=object_class,
        object_name=object_name,
        instance_name=instance_name,
        parameter_name=parameter_name,
        metric_name=metric_name,
        host=host,
        message=message,
        msg_ident=msg_ident,
        fingerprint=fingerprint,
        source_identifier=source_identifier,
        notification_group=stringify(raw.get("resp") or raw.get("six_notification_group")),
        notification_type=stringify(raw.get("resp_type") or raw.get("six_notification_type")).upper(),
        raw=raw,
        ingestion_notes=tuple(notes),
    )


def normalize_bhom_event(raw: dict[str, Any]) -> CanonicalEvent:
    notes = []
    creation_time = parse_timestamp(raw.get("creation_time"))
    if creation_time is None and raw.get("creation_time"):
        notes.append("unparsed_creation_time")

    object_name = stringify(raw.get("object"))
    instance_name = stringify(raw.get("p_instance") or raw.get("instancename") or object_name)
    parameter_name = stringify(raw.get("p_parameter"))
    metric_name = stringify(raw.get("metric_name") or raw.get("al_parameter_name"))
    notification_type = stringify(raw.get("six_notification_type_tmp") or raw.get("six_notification_type")).upper()
    msg_ident = stringify(raw.get("six_msg_ident"))
    source_identifier = stringify(raw.get("source_identifier"))
    fingerprint = stringify(raw.get("six_fingerprint")) or build_fingerprint(
        host=stringify(raw.get("source_hostname") or raw.get("p_publish_hostname")),
        object_class=stringify(raw.get("object_class")),
        object_name=object_name,
        instance_name=instance_name,
        parameter_name=parameter_name,
        metric_name=metric_name,
        msg_ident=msg_ident,
    )

    return CanonicalEvent(
        source="bhom",
        event_id=stringify(raw.get("_identifier") or raw.get("_signature") or raw.get("id")),
        creation_time=creation_time,
        status=stringify(raw.get("status") or raw.get("p_status")).upper(),
        severity=stringify(raw.get("severity")).upper(),
        object_class=stringify(raw.get("object_class")),
        object_name=object_name,
        instance_name=instance_name,
        parameter_name=parameter_name,
        metric_name=metric_name,
        host=stringify(raw.get("source_hostname") or raw.get("p_publish_hostname")),
        message=stringify(raw.get("msg")),
        msg_ident=msg_ident,
        fingerprint=fingerprint,
        source_identifier=source_identifier,
        notification_group=stringify(raw.get("six_notification_group")),
        notification_type=notification_type,
        raw=raw,
        ingestion_notes=tuple(notes),
    )


def parse_timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, int):
        return datetime.fromtimestamp(value / 1000, tz=UTC) if abs(value) >= 10**12 else datetime.fromtimestamp(value, tz=UTC)
    if isinstance(value, float):
        return datetime.fromtimestamp(value / 1000, tz=UTC) if abs(value) >= 10**12 else datetime.fromtimestamp(value, tz=UTC)

    text = stringify(value)
    if not text:
        return None
    if text.isdigit():
        numeric = int(text)
        return datetime.fromtimestamp(numeric / 1000, tz=UTC) if abs(numeric) >= 10**12 else datetime.fromtimestamp(numeric, tz=UTC)

    if re.fullmatch(r"\d{14}\.\d{6}[+-]\d{3}", text):
        match = re.match(r"^(\d{14})\.\d{6}([+-])(\d{3})$", text)
        if match:
            base, sign, offset = match.groups()
            local_time = datetime.strptime(base, "%Y%m%d%H%M%S")
            offset_minutes = int(offset)
            if sign == "+":
                return local_time.replace(tzinfo=UTC)  # fallback if offset is non-standard
            return local_time.replace(tzinfo=UTC)

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def stringify(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def extract_msg_ident(message: str) -> str:
    match = re.search(r"(?:/|//)msgident=([^/]+)", message)
    return stringify(match.group(1) if match else "")


def extract_metric_name(message: str) -> str:
    patterns = [
        r"\b([A-Za-z][A-Za-z0-9_]+)\s+is in\s+(?:CRITICAL|WARNING|MAJOR|MINOR|OK)\b",
        r"\b([A-Za-z][A-Za-z0-9_]+)\s+is above\b",
        r"\b([A-Za-z][A-Za-z0-9_]+)\s+is below\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, message)
        if match:
            return stringify(match.group(1))
    return ""


def extract_instance_hint(message: str) -> str:
    patterns = [
        r"\binstance\s+([^):\s]+(?::\d+)?)",
        r"^\w+\|([^|_]+(?:\.[^|_]+)*)_3182\|",
    ]
    for pattern in patterns:
        match = re.search(pattern, message, flags=re.IGNORECASE)
        if match:
            return stringify(match.group(1))
    return ""


def extract_parameter_hint(message: str) -> str:
    match = re.search(r"\bLABELS\s*=\s*map\[[^\]]*__name__:(\w+)", message)
    if match:
        return stringify(match.group(1))
    return ""


def build_fingerprint(
    *,
    host: str,
    object_class: str,
    object_name: str,
    instance_name: str,
    parameter_name: str,
    metric_name: str,
    msg_ident: str,
) -> str:
    parts = [
        normalize_fingerprint_token(host),
        normalize_fingerprint_token(object_class),
        normalize_fingerprint_token(msg_ident or instance_name or object_name),
        normalize_fingerprint_token(metric_name or parameter_name),
    ]
    return "".join(part for part in parts if part)


def normalize_fingerprint_token(value: str) -> str:
    compact = stringify(value).split(".", 1)[0]
    return re.sub(r"[^A-Za-z0-9_]+", "", compact)
