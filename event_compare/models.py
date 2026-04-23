from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class CanonicalEvent:
    source: str
    event_id: str
    creation_time: datetime | None
    status: str
    severity: str
    object_class: str
    object_name: str
    instance_name: str
    parameter_name: str
    metric_name: str
    host: str
    message: str
    msg_ident: str
    fingerprint: str
    source_identifier: str
    notification_group: str
    notification_type: str
    raw: dict[str, Any]
    ingestion_notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "event_id": self.event_id,
            "creation_time": self.creation_time.isoformat() if self.creation_time else "",
            "status": self.status,
            "severity": self.severity,
            "object_class": self.object_class,
            "object_name": self.object_name,
            "instance_name": self.instance_name,
            "parameter_name": self.parameter_name,
            "metric_name": self.metric_name,
            "host": self.host,
            "message": self.message,
            "msg_ident": self.msg_ident,
            "fingerprint": self.fingerprint,
            "source_identifier": self.source_identifier,
            "notification_group": self.notification_group,
            "notification_type": self.notification_type,
            "ingestion_notes": list(self.ingestion_notes),
        }


@dataclass(frozen=True)
class LoadResult:
    source: str
    events: list[CanonicalEvent]
    issues: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
