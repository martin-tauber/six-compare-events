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
    score_breakdown: dict[str, int]
    time_delta_seconds: int | None
    message_similarity: float

    def as_dict(self) -> dict[str, object]:
        return {
            "event": self.event.as_dict(),
            "score": self.score,
            "confidence": self.confidence,
            "matched_on": self.matched_on,
            "score_breakdown": self.score_breakdown,
            "time_delta_seconds": self.time_delta_seconds,
            "message_similarity": round(self.message_similarity, 3),
        }


def compare_critical_presence(
    truesight_events: Iterable[CanonicalEvent],
    bhom_events: Iterable[CanonicalEvent],
) -> dict[str, object]:
    return analyze_critical_events(
        primary_events=truesight_events,
        candidate_events=bhom_events,
        primary_label="truesight",
        candidate_label="bhom",
    )


def analyze_critical_events(
    *,
    primary_events: Iterable[CanonicalEvent],
    candidate_events: Iterable[CanonicalEvent],
    primary_label: str,
    candidate_label: str,
) -> dict[str, object]:
    primary_critical = [event for event in primary_events if event.severity == "CRITICAL"]
    candidate_materialized = list(candidate_events)
    indexes = build_indexes(candidate_materialized)

    matched: list[dict[str, object]] = []
    matched_to_critical: list[dict[str, object]] = []
    matched_to_noncritical: list[dict[str, object]] = []
    unmatched: list[dict[str, object]] = []
    ambiguous: list[dict[str, object]] = []

    primary_event_key = f"{primary_label}_event"
    candidate_event_key = f"{candidate_label}_event"

    for event in sorted(primary_critical, key=sort_key):
        candidates = match_event_against_pool(event, indexes)
        if not candidates:
            unmatched.append(build_unmatched_record(event, primary_event_key, "No candidate found with overlapping key fields."))
            continue

        top = candidates[0]
        second = candidates[1] if len(candidates) > 1 else None

        if top.score < 55:
            unmatched.append(build_unmatched_record(event, primary_event_key, "Candidates were found, but none passed the minimum score."))
            continue

        if second and is_ambiguous(top, second):
            ambiguous.append(
                {
                    primary_event_key: event.as_dict(),
                    "top_candidates": [candidate.as_dict() for candidate in candidates[:3]],
                    "reason": build_ambiguity_reason(top, second),
                }
            )
            continue

        pair = build_matched_record(
            event,
            top,
            primary_event_key=primary_event_key,
            candidate_event_key=candidate_event_key,
        )
        matched.append(pair)
        if top.event.severity == "CRITICAL":
            matched_to_critical.append(pair)
        else:
            matched_to_noncritical.append(pair)

    summary = {
        f"critical_events_in_{primary_label}": len(primary_critical),
        "matched_count": len(matched),
        "matched_to_critical_count": len(matched_to_critical),
        "matched_to_noncritical_count": len(matched_to_noncritical),
        "unmatched_count": len(unmatched),
        "ambiguous_count": len(ambiguous),
        "coverage_pct": round((len(matched) / len(primary_critical) * 100), 2) if primary_critical else 0.0,
        "critical_match_pct": round((len(matched_to_critical) / len(primary_critical) * 100), 2) if primary_critical else 0.0,
        "top_unmatched_object_classes": top_unmatched_object_classes(unmatched, primary_event_key),
    }

    return {
        "summary": summary,
        "matched": matched,
        "matched_to_critical": matched_to_critical,
        "matched_to_noncritical": matched_to_noncritical,
        "unmatched": unmatched,
        "ambiguous": ambiguous,
    }


def build_indexes(events: list[CanonicalEvent]) -> dict[str, dict[tuple[str, ...], list[CanonicalEvent]]]:
    indexes: dict[str, dict[tuple[str, ...], list[CanonicalEvent]]] = {
        "full_identity": defaultdict(list),
        "fingerprint": defaultdict(list),
        "host": defaultdict(list),
    }

    for event in events:
        host = normalize_host(event.host)
        fingerprint = normalize_text(event.fingerprint)
        identity = build_identity_key(event)

        if all(identity):
            indexes["full_identity"][identity].append(event)
        if fingerprint:
            indexes["fingerprint"][(fingerprint,)].append(event)
        if host:
            indexes["host"][(host,)].append(event)

    return indexes


def collect_candidates(
    event: CanonicalEvent,
    indexes: dict[str, dict[tuple[str, ...], list[CanonicalEvent]]],
) -> list[CanonicalEvent]:
    candidate_map: dict[str, CanonicalEvent] = {}
    fingerprint = normalize_text(event.fingerprint)
    identity = build_identity_key(event)

    if fingerprint:
        for candidate in indexes["fingerprint"].get((fingerprint,), []):
            candidate_map[candidate.event_id] = candidate

    if all(identity):
        for candidate in indexes["full_identity"].get(identity, []):
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


def match_event_against_pool(
    event: CanonicalEvent,
    indexes: dict[str, dict[tuple[str, ...], list[CanonicalEvent]]],
) -> list[CandidateScore]:
    candidates = collect_candidates(event, indexes)
    fallback_candidates = collect_message_time_fallback_candidates(event, indexes, candidates)
    if fallback_candidates:
        candidates = merge_candidates(candidates, fallback_candidates)
    return score_candidates(event, candidates)


def score_candidate(event: CanonicalEvent, candidate: CanonicalEvent) -> CandidateScore:
    matched_on: list[str] = []
    score = 0
    score_breakdown: dict[str, int] = {}
    same_fingerprint = normalize_text(event.fingerprint) and normalize_text(event.fingerprint) == normalize_text(candidate.fingerprint)
    same_host = normalize_host(event.host) and normalize_host(event.host) == normalize_host(candidate.host)
    identity = build_identity_key(event)
    same_identity = all(identity) and identity == build_identity_key(candidate)

    if same_fingerprint:
        score += add_score(score_breakdown, "fingerprint", 120)
        matched_on.append("fingerprint")

    if same_identity:
        score += add_score(score_breakdown, "full_identity", 110)
        matched_on.append("full_identity")

    if same_host:
        score += add_score(score_breakdown, "host", 25)
        matched_on.append("host")

    time_delta = time_delta_seconds(event.creation_time, candidate.creation_time)
    if time_delta is not None and same_host:
        if time_delta <= 300:
            score += add_score(score_breakdown, "time<=5m", 25)
            matched_on.append("time<=5m")
        elif time_delta <= 900:
            score += add_score(score_breakdown, "time<=15m", 20)
            matched_on.append("time<=15m")
        elif time_delta <= 3600:
            score += add_score(score_breakdown, "time<=1h", 12)
            matched_on.append("time<=1h")
        elif time_delta <= 10800:
            score += add_score(score_breakdown, "time<=3h", 6)
            matched_on.append("time<=3h")

    left_signature = message_signature(event.message)
    right_signature = message_signature(candidate.message)
    similarity = SequenceMatcher(None, left_signature, right_signature).ratio() if left_signature and right_signature else 0.0
    if same_host and left_signature and right_signature:
        if left_signature == right_signature:
            score += add_score(score_breakdown, "message_signature", 45)
            matched_on.append("message_signature")
        elif similarity > 0:
            score += add_score(score_breakdown, "message_similarity", round(similarity * 45))
            matched_on.append("message_similarity")

    if same_host and not same_fingerprint and not same_identity:
        add_score(score_breakdown, "message_time_fallback", 0)
        matched_on.append("message_time_fallback")

    confidence = "low"
    if score >= 110:
        confidence = "high"
    elif score >= 75:
        confidence = "medium"

    return CandidateScore(
        event=candidate,
        score=score,
        confidence=confidence,
        matched_on=matched_on,
        score_breakdown=score_breakdown,
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


def build_unmatched_record(event: CanonicalEvent, event_key: str, reason: str) -> dict[str, object]:
    return {
        event_key: event.as_dict(),
        "reason": reason,
    }


def build_matched_record(
    event: CanonicalEvent,
    top: CandidateScore,
    *,
    primary_event_key: str,
    candidate_event_key: str,
) -> dict[str, object]:
    return {
        primary_event_key: event.as_dict(),
        candidate_event_key: top.event.as_dict(),
        "score": top.score,
        "confidence": top.confidence,
        "matched_on": top.matched_on,
        "score_breakdown": top.score_breakdown,
        "time_delta_seconds": top.time_delta_seconds,
        "message_similarity": round(top.message_similarity, 3),
        "severity_alignment": "critical" if top.event.severity == "CRITICAL" else "noncritical",
        "responsibility_alignment": compare_responsibility(event, top.event),
        "notification_alignment": compare_notification_type(event, top.event),
    }


def compare_responsibility(left: CanonicalEvent, right: CanonicalEvent) -> str:
    left_group = normalize_text(left.notification_group)
    right_group = normalize_text(right.notification_group)
    if not left_group or not right_group:
        return "missing"
    if left_group == right_group:
        return "match"
    return "mismatch"


def compare_notification_type(left: CanonicalEvent, right: CanonicalEvent) -> str:
    left_type = normalize_notification_type(left.notification_type)
    right_type = normalize_notification_type(right.notification_type)
    if not left_type and not right_type:
        return "match"
    if not left_type:
        return "mismatch"
    if not right_type:
        return "missing"
    if left_type == right_type:
        return "match"
    return "mismatch"


def normalize_notification_type(value: str) -> str:
    normalized = normalize_text(value)
    if normalized == "undefined":
        return ""
    return normalized


def top_unmatched_object_classes(unmatched: list[dict[str, object]], event_key: str) -> list[dict[str, object]]:
    counts: dict[str, int] = {}
    for item in unmatched:
        event = item[event_key]
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


def build_ambiguity_reason(top: CandidateScore, second: CandidateScore) -> str:
    top_delta = format_time_delta(top.time_delta_seconds)
    second_delta = format_time_delta(second.time_delta_seconds)
    shared_signals = sorted(set(top.matched_on) & set(second.matched_on))
    signal_text = ", ".join(shared_signals) if shared_signals else "no shared signals recorded"
    return (
        "Top candidates remain too close to choose safely. "
        f"{top.event.event_id}: score {top.score}, message similarity {top.message_similarity:.3f}, "
        f"time delta {top_delta}, matched on [{', '.join(top.matched_on)}]. "
        f"{second.event.event_id}: score {second.score}, message similarity {second.message_similarity:.3f}, "
        f"time delta {second_delta}, matched on [{', '.join(second.matched_on)}]. "
        f"Shared signals: {signal_text}."
    )


def format_time_delta(value: int | None) -> str:
    if value is None:
        return "unknown"
    return f"{value}s"


def collect_message_time_fallback_candidates(
    event: CanonicalEvent,
    indexes: dict[str, dict[tuple[str, ...], list[CanonicalEvent]]],
    existing_candidates: list[CanonicalEvent],
) -> list[CanonicalEvent]:
    existing_ids = {candidate.event_id for candidate in existing_candidates}
    left_signature = message_signature(event.message)
    event_host = normalize_host(event.host)
    if not event_host or not left_signature or event.creation_time is None:
        return []

    fallback_candidates: list[CanonicalEvent] = []

    for candidate in indexes["host"].get((event_host,), []):
        if candidate.event_id in existing_ids or candidate.creation_time is None:
            continue

        delta = time_delta_seconds(event.creation_time, candidate.creation_time)
        if delta is None or delta > 10800:
            continue

        right_signature = message_signature(candidate.message)
        if not right_signature:
            continue

        similarity = SequenceMatcher(None, left_signature, right_signature).ratio()
        if similarity >= 0.55:
            fallback_candidates.append(candidate)

    return fallback_candidates


def build_identity_key(event: CanonicalEvent) -> tuple[str, str, str, str, str]:
    return (
        normalize_host(event.host),
        normalize_text(event.object_class),
        normalize_text(event.object_name),
        normalize_text(event.instance_name),
        normalized_metric_parameter(event),
    )


def normalized_metric_parameter(event: CanonicalEvent) -> str:
    return normalize_text(event.metric_name or event.parameter_name)


def merge_candidates(
    left: list[CanonicalEvent],
    right: list[CanonicalEvent],
) -> list[CanonicalEvent]:
    merged = {candidate.event_id: candidate for candidate in left}
    for candidate in right:
        merged[candidate.event_id] = candidate
    return list(merged.values())


def add_score(score_breakdown: dict[str, int], key: str, value: int) -> int:
    score_breakdown[key] = score_breakdown.get(key, 0) + value
    return value
