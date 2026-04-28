from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import CanonicalEvent, LoadResult


def load_truesight_events(path: str | Path) -> LoadResult:
    file_path = Path(path)
    text, encoding = read_text_with_fallback(file_path)
    issues: list[dict[str, Any]]

    if file_path.suffix.lower() == ".baroc":
        raw_events, issues = parse_truesight_baroc(text)
        if encoding != "utf-8":
            issues.append(
                {
                    "source": "truesight",
                    "kind": "non_utf8_input",
                    "message": f"Decoded input with fallback encoding {encoding}.",
                    "encoding": encoding,
                }
            )
        metadata = {
            "path": str(file_path),
            "parser": "baroc",
            "encoding": encoding,
            "event_count": len(raw_events),
        }
    else:
        issues = []
        try:
            raw_events = json.loads(text)
            metadata = {
                "path": str(file_path),
                "parser": "json",
                "encoding": encoding,
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
                "encoding": encoding,
                "event_count": len(raw_events),
            }

    events = [normalize_truesight_event(event) for event in raw_events]
    return LoadResult(source="truesight", events=events, issues=issues, metadata=metadata)


def read_text_with_fallback(path: Path) -> tuple[str, str]:
    payload = path.read_bytes()
    try:
        return payload.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        try:
            return payload.decode("cp1252"), "cp1252"
        except UnicodeDecodeError:
            return payload.decode("latin-1"), "latin-1"


def load_bhom_events(path: str | Path) -> LoadResult:
    file_path = Path(path)
    raw_events, parser_name, response_count, reported_total = parse_bhom_payload(file_path.read_text())

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
        "parser": parser_name,
        "responses": response_count,
        "event_count": len(events),
        "reported_total": reported_total,
    }
    return LoadResult(source="bhom", events=events, issues=issues, metadata=metadata)


def parse_bhom_payload(text: str) -> tuple[list[dict[str, Any]], str, int, int]:
    stripped = text.strip()
    if not stripped:
        return [], "empty", 0, 0

    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        raw_events, response_count, reported_total = parse_bhom_jsonl(text)
        return raw_events, "jsonl", response_count, reported_total

    raw_events, response_count, reported_total = extract_bhom_raw_events(payload)
    return raw_events, "json", response_count, reported_total


def parse_bhom_jsonl(text: str) -> tuple[list[dict[str, Any]], int, int]:
    raw_events: list[dict[str, Any]] = []
    response_count = 0
    reported_total = 0

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        payload = json.loads(stripped)
        line_events, line_response_count, line_reported_total = extract_bhom_raw_events(payload)
        raw_events.extend(line_events)
        response_count += line_response_count
        reported_total += line_reported_total

    return raw_events, response_count, reported_total


def extract_bhom_raw_events(payload: Any) -> tuple[list[dict[str, Any]], int, int]:
    if isinstance(payload, list):
        raw_events: list[dict[str, Any]] = []
        response_count = 0
        reported_total = 0
        for entry in payload:
            entry_events, entry_response_count, entry_reported_total = extract_bhom_raw_events(entry)
            raw_events.extend(entry_events)
            response_count += entry_response_count
            reported_total += entry_reported_total
        return raw_events, response_count, reported_total

    if not isinstance(payload, dict):
        raise ValueError("Unsupported BHOM payload: expected a JSON object, array, or JSON Lines input.")

    if "responses" in payload:
        raw_events: list[dict[str, Any]] = []
        response_count = 0
        reported_total = 0
        for response in payload.get("responses", []):
            response_events, nested_response_count, nested_reported_total = extract_bhom_raw_events(response)
            raw_events.extend(response_events)
            response_count += nested_response_count
            reported_total += nested_reported_total
        return raw_events, response_count, reported_total

    if "hits" in payload:
        hits = payload.get("hits", {})
        total = hits.get("total", {}) if isinstance(hits, dict) else {}
        reported_total = 0
        if isinstance(total, dict):
            reported_total = int(total.get("value", 0) or 0)
        line_hits = hits.get("hits", []) if isinstance(hits, dict) else []
        raw_events = [hit.get("_source", {}) for hit in line_hits if isinstance(hit, dict)]
        return raw_events, 1, reported_total

    if "_source" in payload and isinstance(payload["_source"], dict):
        return [payload["_source"]], 0, 0

    return [payload], 0, 0


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
    message = stringify(raw.get("msg"))
    metric_name = extract_metric_name(message)
    instance_name = (
        stringify(raw.get("mc_object") or raw.get("object"))
        or stringify(raw.get("p_instance") or raw.get("instancename"))
        or extract_instance_hint(message)
    )
    object_name = instance_name
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
        event_id=stringify(raw.get("mc_ueid") or raw.get("event_handle") or raw.get("_identifier")),
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
        notification_type=derive_truesight_notification_type(raw),
        raw=raw,
        stage=stringify(raw.get("prod_category")).upper(),
        ingestion_notes=tuple(notes),
    )


def normalize_bhom_event(raw: dict[str, Any]) -> CanonicalEvent:
    notes = []
    creation_time = parse_timestamp(raw.get("creation_time"))
    if creation_time is None and raw.get("creation_time"):
        notes.append("unparsed_creation_time")

    instance_name = stringify(raw.get("instancename") or raw.get("p_instance") or raw.get("object"))
    object_name = instance_name
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
        stage="",
        ingestion_notes=tuple(notes),
    )


def derive_truesight_notification_type(raw: dict[str, Any]) -> str:
    alarm_type = stringify(raw.get("alarm_type")).upper()
    resp_type = stringify(raw.get("resp_type")).upper()
    with_ars = stringify(raw.get("with_ars")).upper()
    if "AUTO" not in alarm_type:
        return ""
    if ("PAGER" in resp_type or "ALL" in resp_type) and "TRUE" in with_ars:
        return "ONCALL_ITSM"
    if "PAGER" in resp_type or "ALL" in resp_type:
        return "ONCALL"
    if "ITSM" in resp_type:
        return "ITSM"
    if "MAIL" in resp_type:
        return "MAIL"
    return stringify(raw.get("six_notification_type")).upper()


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
