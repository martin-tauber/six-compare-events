from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from difflib import SequenceMatcher
from typing import Iterable

from .models import CanonicalEvent


@dataclass(frozen=True)
class CandidateScore:
    event: CanonicalEvent
    score: int
    confidence: str
    matched_on: list[str]
    time_delta_seconds: int | None
    message_similarity: float

    def as_dict(self) -> dict[str, object]:
        return {
            "event": self.event.as_dict(),
            "score": self.score,
            "confidence": self.confidence,
            "matched_on": self.matched_on,
            "time_delta_seconds": self.time_delta_seconds,
            "message_similarity": round(self.message_similarity, 3),
        }


def compare_critical_presence(
    truesight_events: Iterable[CanonicalEvent],
    bhom_events: Iterable[CanonicalEvent],
) -> dict[str, object]:
    truesight_critical = [event for event in truesight_events if event.severity == "CRITICAL"]
    bhom_materialized = list(bhom_events)
    indexes = build_indexes(bhom_materialized)

    matched: list[dict[str, object]] = []
    unmatched: list[dict[str, object]] = []
    ambiguous: list[dict[str, object]] = []

    for event in sorted(truesight_critical, key=sort_key):
        candidates = collect_candidates(event, indexes)
        scored_candidates = score_candidates(event, candidates)
        if not scored_candidates or scored_candidates[0].score < 55:
            fallback_candidates = collect_message_time_fallback_candidates(event, bhom_materialized, candidates)
            if fallback_candidates:
                candidates = merge_candidates(candidates, fallback_candidates)
                scored_candidates = score_candidates(event, candidates)

        candidates = scored_candidates
        if not candidates:
            unmatched.append(build_unmatched_record(event, "No BHOM candidate found with overlapping key fields."))
            continue

        top = candidates[0]
        second = candidates[1] if len(candidates) > 1 else None

        if top.score < 55:
            unmatched.append(build_unmatched_record(event, "Candidates were found, but none passed the minimum score."))
            continue

        if second and is_ambiguous(top, second):
            ambiguous.append(
                {
                    "truesight_event": event.as_dict(),
                    "top_candidates": [candidate.as_dict() for candidate in candidates[:3]],
                    "reason": "Multiple BHOM candidates have similarly strong scores.",
                }
            )
            continue

        matched.append(
            {
                "truesight_event": event.as_dict(),
                "bhom_event": top.event.as_dict(),
                "score": top.score,
                "confidence": top.confidence,
                "matched_on": top.matched_on,
                "time_delta_seconds": top.time_delta_seconds,
                "message_similarity": round(top.message_similarity, 3),
            }
        )

    summary = {
        "critical_events_in_truesight": len(truesight_critical),
        "matched_count": len(matched),
        "unmatched_count": len(unmatched),
        "ambiguous_count": len(ambiguous),
        "coverage_pct": round((len(matched) / len(truesight_critical) * 100), 2) if truesight_critical else 0.0,
        "top_unmatched_object_classes": top_unmatched_object_classes(unmatched),
    }

    return {
        "summary": summary,
        "matched": matched,
        "unmatched": unmatched,
        "ambiguous": ambiguous,
    }


def build_indexes(events: list[CanonicalEvent]) -> dict[str, dict[tuple[str, ...], list[CanonicalEvent]]]:
    indexes: dict[str, dict[tuple[str, ...], list[CanonicalEvent]]] = {
        "class_object_host": defaultdict(list),
        "class_instance_host": defaultdict(list),
        "class_object": defaultdict(list),
        "object_host": defaultdict(list),
        "class_host": defaultdict(list),
        "object": defaultdict(list),
        "msg_ident_host": defaultdict(list),
        "fingerprint": defaultdict(list),
    }

    for event in events:
        object_class = normalize_text(event.object_class)
        object_name = normalize_text(event.object_name)
        instance_name = normalize_text(event.instance_name)
        msg_ident = normalize_text(event.msg_ident)
        host = normalize_host(event.host)
        fingerprint = normalize_text(event.fingerprint)

        indexes["class_object_host"][(object_class, object_name, host)].append(event)
        indexes["class_instance_host"][(object_class, instance_name, host)].append(event)
        indexes["class_object"][(object_class, object_name)].append(event)
        indexes["object_host"][(object_name, host)].append(event)
        indexes["class_host"][(object_class, host)].append(event)
        indexes["object"][(object_name,)].append(event)
        indexes["msg_ident_host"][(msg_ident, host)].append(event)
        indexes["fingerprint"][(fingerprint,)].append(event)

    return indexes


def collect_candidates(
    event: CanonicalEvent,
    indexes: dict[str, dict[tuple[str, ...], list[CanonicalEvent]]],
) -> list[CanonicalEvent]:
    object_class = normalize_text(event.object_class)
    object_name = normalize_text(event.object_name)
    instance_name = normalize_text(event.instance_name)
    msg_ident = normalize_text(event.msg_ident)
    host = normalize_host(event.host)
    fingerprint = normalize_text(event.fingerprint)

    candidate_map: dict[str, CanonicalEvent] = {}
    keys = [
        ("fingerprint", (fingerprint,)),
        ("class_object_host", (object_class, object_name, host)),
        ("class_instance_host", (object_class, instance_name, host)),
        ("class_object", (object_class, object_name)),
        ("object_host", (object_name, host)),
        ("class_host", (object_class, host)),
        ("object", (object_name,)),
        ("msg_ident_host", (msg_ident, host)),
    ]

    for index_name, key in keys:
        if not all(key):
            continue
        for candidate in indexes[index_name].get(key, []):
            candidate_map[candidate.event_id] = candidate

    return list(candidate_map.values())


def score_candidates(event: CanonicalEvent, candidates: list[CanonicalEvent]) -> list[CandidateScore]:
    scored = [score_candidate(event, candidate) for candidate in candidates]
    return sorted(
        scored,
        key=lambda candidate: (
            -candidate.score,
            -candidate.message_similarity,
            candidate.time_delta_seconds or 10**9,
            candidate.event.event_id,
        ),
    )


def score_candidate(event: CanonicalEvent, candidate: CanonicalEvent) -> CandidateScore:
    matched_on: list[str] = []
    score = 0
    same_object_class = normalize_text(event.object_class) and normalize_text(event.object_class) == normalize_text(candidate.object_class)
    same_object_name = normalize_text(event.object_name) and normalize_text(event.object_name) == normalize_text(candidate.object_name)
    same_instance_name = normalize_text(event.instance_name) and normalize_text(event.instance_name) == normalize_text(candidate.instance_name)
    same_msg_ident = normalize_text(event.msg_ident) and normalize_text(event.msg_ident) == normalize_text(candidate.msg_ident or candidate.object_name)
    same_fingerprint = normalize_text(event.fingerprint) and normalize_text(event.fingerprint) == normalize_text(candidate.fingerprint)
    same_metric_name = normalize_text(event.metric_name) and normalize_text(event.metric_name) == normalize_text(candidate.metric_name)
    same_host = normalize_host(event.host) and normalize_host(event.host) == normalize_host(candidate.host)
    object_to_instance = normalize_text(event.object_name) and normalize_text(event.object_name) == normalize_text(candidate.instance_name)

    if same_object_class:
        score += 35
        matched_on.append("object_class")

    if same_object_name:
        score += 35
        matched_on.append("object")

    if same_instance_name:
        score += 25
        matched_on.append("instance")

    if same_msg_ident:
        score += 22
        matched_on.append("msg_ident")

    if same_fingerprint:
        score += 28
        matched_on.append("fingerprint")

    if same_metric_name:
        score += 18
        matched_on.append("metric_name")

    if same_host:
        score += 20
        matched_on.append("host")

    if object_to_instance:
        score += 14
        matched_on.append("object_to_instance")

    time_delta = time_delta_seconds(event.creation_time, candidate.creation_time)
    if time_delta is not None:
        if time_delta <= 300:
            score += 12
            matched_on.append("time<=5m")
        elif time_delta <= 3600:
            score += 8
            matched_on.append("time<=1h")
        elif time_delta <= 10800:
            score += 5
            matched_on.append("time<=3h")

    if event.notification_group and event.notification_group == candidate.notification_group:
        score += 4
        matched_on.append("notification_group")

    if event.severity and event.severity == candidate.severity:
        score += 3
        matched_on.append("severity")

    left_signature = message_signature(event.message)
    right_signature = message_signature(candidate.message)
    similarity = SequenceMatcher(None, left_signature, right_signature).ratio() if left_signature and right_signature else 0.0
    if left_signature and right_signature:
        if left_signature == right_signature:
            score += 10
            matched_on.append("message_signature")
        elif similarity >= 0.9:
            score += 8
            matched_on.append("message_similarity>=0.9")
        elif similarity >= 0.75:
            score += 5
            matched_on.append("message_similarity>=0.75")

    if time_delta is not None and time_delta <= 10800:
        if same_host and left_signature and left_signature == right_signature:
            score += 18
            matched_on.append("message_time_fallback")
        elif same_host and same_object_class and similarity >= 0.97:
            score += 12
            matched_on.append("message_time_fallback")

    confidence = "low"
    if score >= 95:
        confidence = "high"
    elif score >= 70:
        confidence = "medium"

    return CandidateScore(
        event=candidate,
        score=score,
        confidence=confidence,
        matched_on=matched_on,
        time_delta_seconds=time_delta,
        message_similarity=similarity,
    )


def message_signature(message: str) -> str:
    text = normalize_text(message)
    if not text:
        return ""

    text = text.split("/date=")[0]
    text = re.sub(r"[a-f0-9]{8,}", "<hex>", text)
    text = re.sub(r"\b\d{4,}\b", "<num>", text)
    text = re.sub(r"\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}z?", "<timestamp>", text)
    text = re.sub(r"\s+", " ", text)
    return text[:240]


def normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def normalize_host(value: str) -> str:
    host = normalize_text(value)
    return host.split(".", 1)[0] if host else ""


def time_delta_seconds(left: datetime | None, right: datetime | None) -> int | None:
    if left is None or right is None:
        return None
    return abs(int((left - right).total_seconds()))


def sort_key(event: CanonicalEvent) -> tuple[str, str, str, str]:
    return (event.object_class, event.object_name, event.host, event.event_id)


def build_unmatched_record(event: CanonicalEvent, reason: str) -> dict[str, object]:
    return {
        "truesight_event": event.as_dict(),
        "reason": reason,
    }


def top_unmatched_object_classes(unmatched: list[dict[str, object]]) -> list[dict[str, object]]:
    counts: dict[str, int] = {}
    for item in unmatched:
        event = item["truesight_event"]
        object_class = str(event.get("object_class") or "UNKNOWN")
        counts[object_class] = counts.get(object_class, 0) + 1
    return [
        {"object_class": object_class, "count": count}
        for object_class, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:10]
    ]


def is_ambiguous(top: CandidateScore, second: CandidateScore) -> bool:
    if top.score - second.score > 2:
        return False
    if abs(top.message_similarity - second.message_similarity) >= 0.03:
        return False
    top_delta = top.time_delta_seconds if top.time_delta_seconds is not None else 10**9
    second_delta = second.time_delta_seconds if second.time_delta_seconds is not None else 10**9
    if second_delta - top_delta > 600:
        return False
    return True


def collect_message_time_fallback_candidates(
    event: CanonicalEvent,
    bhom_events: list[CanonicalEvent],
    existing_candidates: list[CanonicalEvent],
) -> list[CanonicalEvent]:
    existing_ids = {candidate.event_id for candidate in existing_candidates}
    left_signature = message_signature(event.message)
    if not left_signature or event.creation_time is None:
        return []

    fallback_candidates: list[CanonicalEvent] = []
    event_host = normalize_host(event.host)
    event_class = normalize_text(event.object_class)
    event_notification_group = normalize_text(event.notification_group)

    for candidate in bhom_events:
        if candidate.event_id in existing_ids or candidate.creation_time is None:
            continue

        delta = time_delta_seconds(event.creation_time, candidate.creation_time)
        if delta is None or delta > 10800:
            continue

        right_signature = message_signature(candidate.message)
        if not right_signature:
            continue

        similarity = SequenceMatcher(None, left_signature, right_signature).ratio()
        same_host = bool(event_host and event_host == normalize_host(candidate.host))
        same_class = bool(event_class and event_class == normalize_text(candidate.object_class))
        same_notification_group = bool(
            event_notification_group and event_notification_group == normalize_text(candidate.notification_group)
        )

        if same_host and left_signature == right_signature:
            fallback_candidates.append(candidate)
            continue

        if same_host and same_class and similarity >= 0.97:
            fallback_candidates.append(candidate)
            continue

        if same_class and same_notification_group and left_signature == right_signature and delta <= 3600:
            fallback_candidates.append(candidate)

    return fallback_candidates


def merge_candidates(
    left: list[CanonicalEvent],
    right: list[CanonicalEvent],
) -> list[CanonicalEvent]:
    merged = {candidate.event_id: candidate for candidate in left}
    for candidate in right:
        merged[candidate.event_id] = candidate
    return list(merged.values())
