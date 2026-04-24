from __future__ import annotations

import json
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any


def write_browser_report(
    output_path: str | Path,
    *,
    summary: dict[str, Any],
    truesight_to_bhom: dict[str, Any],
) -> None:
    path = Path(output_path)
    payload = build_browser_payload(summary=summary, truesight_to_bhom=truesight_to_bhom)
    path.write_text(render_browser_html(payload), encoding="utf-8")


def write_matching_documentation(
    output_path: str | Path,
    *,
    summary: dict[str, Any],
) -> None:
    path = Path(output_path)
    path.write_text(render_matching_documentation_html(summary), encoding="utf-8")


def write_mapping_documentation(
    output_path: str | Path,
    *,
    summary: dict[str, Any],
) -> None:
    path = Path(output_path)
    path.write_text(render_mapping_documentation_html(summary), encoding="utf-8")


def write_statistics_report(
    output_path: str | Path,
    *,
    current_snapshot: dict[str, Any],
    history: list[dict[str, Any]],
) -> None:
    path = Path(output_path)
    path.write_text(render_statistics_html(current_snapshot=current_snapshot, history=history), encoding="utf-8")


def coverage_percent(count: int, total: int) -> str:
    return f"{(count / total * 100):.2f}%" if total else "0.00%"


def format_header_timestamp(value: str) -> str:
    if not value:
        return "-"
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return value


def build_issue_notes(issues: list[dict[str, Any]], *, docs_mode: bool = False) -> list[str]:
    notes: list[str] = []
    for issue in issues:
        if issue.get("kind") == "partial_export":
            if docs_mode:
                notes.append(
                    f"Current BHOM sample is partial: {issue['materialized_hits']} hits are present in the file "
                    f"while {issue['reported_total']} were reported by the export."
                )
            else:
                notes.append(
                    f"BHOM export is partial: {issue['materialized_hits']} hits materialized "
                    f"while {issue['reported_total']} were reported."
                )
        elif issue.get("kind") == "analysis_window_limited":
            notes.append(
                f"Analysis was limited to the shared timeframe {format_header_timestamp(str(issue.get('start_time', '')))} "
                f"to {format_header_timestamp(str(issue.get('end_time', '')))}."
            )
    return notes


def build_browser_payload(
    *,
    summary: dict[str, Any],
    truesight_to_bhom: dict[str, Any],
) -> dict[str, Any]:
    matched_critical_rows = [flatten_matched_row(row) for row in truesight_to_bhom["matched_to_critical"]]
    severity_mismatch_rows = [flatten_matched_row(row) for row in truesight_to_bhom["matched_to_noncritical"]]
    all_matched_rows = matched_critical_rows + severity_mismatch_rows
    responsibility_mismatch_rows = [row for row in all_matched_rows if row["responsibility_alignment"] == "mismatch"]
    notification_mismatch_rows = [row for row in all_matched_rows if row["notification_alignment"] != "match"]
    overall_coverage_rows = [
        row
        for row in all_matched_rows
        if row["severity_alignment"] == "critical"
        and row["responsibility_alignment"] == "match"
        and row["notification_alignment"] == "match"
    ]

    return {
        "summary": summary,
        "overall_coverage_count": len(overall_coverage_rows),
        "responsibility_mismatch_count": len(responsibility_mismatch_rows),
        "notification_mismatch_count": len(notification_mismatch_rows),
        "sections": [
            {
                "id": "matched",
                "label": "Matched",
                "description": "Truesight critical events with an accepted BHOM match, including severity mismatches.",
                "rows": all_matched_rows,
            },
            {
                "id": "severity-mismatch",
                "label": "Severity mismatch",
                "description": "Truesight critical events that match a BHOM event, but BHOM is not critical.",
                "rows": severity_mismatch_rows,
            },
            {
                "id": "responsibility-mismatch",
                "label": "Responsibility mismatch",
                "description": "Accepted matches where Truesight resp and BHOM six_notification_group are different.",
                "rows": responsibility_mismatch_rows,
            },
            {
                "id": "notification-mismatch",
                "label": "Notification mismatch",
                "description": "Accepted matches where the derived Truesight notification type is different from or missing in BHOM six_notification_type.",
                "rows": notification_mismatch_rows,
            },
            {
                "id": "ambiguous",
                "label": "Ambiguous",
                "description": "Truesight critical events with multiple plausible BHOM candidates.",
                "rows": [flatten_ambiguous_row(row) for row in truesight_to_bhom["ambiguous"]],
            },
            {
                "id": "unmatched",
                "label": "No BHOM candidate",
                "description": "Truesight critical events with no BHOM candidate in the sample export.",
                "rows": [flatten_unmatched_row(row) for row in truesight_to_bhom["unmatched"]],
            },
        ],
    }


def flatten_matched_row(row: dict[str, Any]) -> dict[str, Any]:
    truesight_event = row["truesight_event"]
    bhom_event = row["bhom_event"]
    return {
        "kind": "matched",
        "truesight_event_id": truesight_event["event_id"],
        "bhom_event_id": bhom_event["event_id"],
        "message": truesight_event["message"],
        "host": truesight_event["host"],
        "truesight_severity": truesight_event["severity"],
        "bhom_severity": bhom_event["severity"],
        "severity_alignment": row["severity_alignment"],
        "truesight_responsibility": truesight_event["notification_group"],
        "bhom_responsibility": bhom_event["notification_group"],
        "responsibility_alignment": row["responsibility_alignment"],
        "truesight_notification_type": truesight_event["notification_type"],
        "bhom_notification_type": bhom_event["notification_type"],
        "notification_alignment": row["notification_alignment"],
        "truesight_creation_time": truesight_event["creation_time"],
        "bhom_creation_time": bhom_event["creation_time"],
        "notification_group": truesight_event["notification_group"],
        "confidence": row["confidence"],
        "score": row["score"],
        "matched_on": ", ".join(row["matched_on"]),
        "reason": "",
        "search_text": " ".join(
            [
                truesight_event["event_id"],
                bhom_event["event_id"],
                truesight_event["object_class"],
                truesight_event["object_name"],
                truesight_event["host"],
                truesight_event["severity"],
                bhom_event["severity"],
                truesight_event["notification_group"],
                bhom_event["notification_group"],
                truesight_event["notification_type"],
                bhom_event["notification_type"],
                truesight_event["message"],
                bhom_event["message"],
            ]
        ).lower(),
        "details": {
            "truesight_event": truesight_event,
            "bhom_event": bhom_event,
            "score": row["score"],
            "score_breakdown": row["score_breakdown"],
            "confidence": row["confidence"],
            "severity_alignment": row["severity_alignment"],
            "responsibility_alignment": row["responsibility_alignment"],
            "notification_alignment": row["notification_alignment"],
            "matched_on": row["matched_on"],
            "message_similarity": row["message_similarity"],
            "time_delta_seconds": row["time_delta_seconds"],
        },
    }


def flatten_ambiguous_row(row: dict[str, Any]) -> dict[str, Any]:
    truesight_event = row["truesight_event"]
    candidates = row["top_candidates"]
    candidate_ids = [candidate["event"]["event_id"] for candidate in candidates]
    return {
        "kind": "ambiguous",
        "truesight_event_id": truesight_event["event_id"],
        "bhom_event_id": "",
        "message": truesight_event["message"],
        "host": truesight_event["host"],
        "truesight_severity": truesight_event["severity"],
        "bhom_severity": candidate_ids,
        "truesight_responsibility": truesight_event["notification_group"],
        "bhom_responsibility": candidate_ids,
        "responsibility_alignment": "",
        "notification_alignment": "",
        "truesight_creation_time": truesight_event["creation_time"],
        "bhom_creation_time": "",
        "notification_group": truesight_event["notification_group"],
        "confidence": "",
        "score": ", ".join(str(candidate["score"]) for candidate in candidates),
        "matched_on": ", ".join(candidate["event"]["event_id"] for candidate in candidates),
        "reason": row["reason"],
        "search_text": " ".join(
            [
                truesight_event["event_id"],
                truesight_event["object_class"],
                truesight_event["object_name"],
                truesight_event["host"],
                truesight_event["message"],
                " ".join(candidate["event"]["event_id"] for candidate in candidates),
            ]
        ).lower(),
        "details": {
            "truesight_event": truesight_event,
            "top_candidates": candidates,
            "reason": row["reason"],
        },
    }


def flatten_unmatched_row(row: dict[str, Any]) -> dict[str, Any]:
    truesight_event = row["truesight_event"]
    return {
        "kind": "unmatched",
        "truesight_event_id": truesight_event["event_id"],
        "bhom_event_id": "",
        "message": truesight_event["message"],
        "host": truesight_event["host"],
        "truesight_severity": truesight_event["severity"],
        "bhom_severity": "",
        "truesight_responsibility": truesight_event["notification_group"],
        "bhom_responsibility": "",
        "responsibility_alignment": "",
        "notification_alignment": "",
        "truesight_creation_time": truesight_event["creation_time"],
        "bhom_creation_time": "",
        "notification_group": truesight_event["notification_group"],
        "confidence": "",
        "score": "",
        "matched_on": "",
        "reason": row["reason"],
        "search_text": " ".join(
            [
                truesight_event["event_id"],
                truesight_event["object_class"],
                truesight_event["object_name"],
                truesight_event["host"],
                truesight_event["message"],
                row["reason"],
            ]
        ).lower(),
        "details": {
            "truesight_event": truesight_event,
            "reason": row["reason"],
        },
    }


def render_browser_html(payload: dict[str, Any]) -> str:
    data_json = json.dumps(payload, indent=2).replace("</", "<\\/")
    ts_summary = payload["summary"]["truesight_to_bhom"]
    critical_total = ts_summary["critical_events_in_truesight"]
    matched_total = ts_summary["matched_count"]
    overall_coverage = coverage_percent(payload["overall_coverage_count"], critical_total)
    severity_alignment_coverage = coverage_percent(
        matched_total - ts_summary["matched_to_noncritical_count"],
        matched_total,
    )
    responsibility_alignment_coverage = coverage_percent(
        matched_total - payload["responsibility_mismatch_count"],
        matched_total,
    )
    notification_alignment_coverage = coverage_percent(
        matched_total - payload["notification_mismatch_count"],
        matched_total,
    )
    issues = payload["summary"].get("issues", [])
    truesight_meta = payload["summary"].get("truesight", {})
    bhom_meta = payload["summary"].get("bhom", {})
    issue_notes = build_issue_notes(issues)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Event comparison browser</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg: #0b1020;
      --panel: #121933;
      --panel-alt: #172043;
      --text: #e7ebff;
      --muted: #aab4df;
      --accent: #6ea8fe;
      --border: #2a3668;
      --ok: #2ea043;
      --warn: #d29922;
      --bad: #f85149;
    }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    .page {{
      max-width: 1440px;
      margin: 0 auto;
      padding: 24px;
    }}
    .hero, .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 20px;
    }}
    .hero h1 {{
      margin: 0 0 8px;
      font-size: 28px;
    }}
    .subtle {{
      color: var(--muted);
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-top: 18px;
    }}
    .summary-cards {{
      grid-template-columns: repeat(8, minmax(0, 1fr));
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 12px;
      margin-top: 18px;
    }}
    .meta-card {{
      background: var(--panel-alt);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
    }}
    .meta-card strong {{
      display: block;
      margin-bottom: 8px;
    }}
    .card {{
      background: var(--panel-alt);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
    }}
    .summary-cards .card {{
      min-width: 0;
      padding: 12px;
      display: flex;
      flex-direction: column;
    }}
    .card .label {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .06em;
    }}
    .card .value {{
      margin-top: 8px;
      font-size: 28px;
      font-weight: 700;
    }}
    .card .meta {{
      margin-top: 6px;
      color: var(--muted);
      font-size: 12px;
    }}
    .summary-cards .value {{
      font-size: 24px;
    }}
    .summary-cards .meta {{
      font-size: 11px;
    }}
    .summary-cards .label {{
      min-height: 2.6em;
      display: flex;
      align-items: flex-start;
    }}
    .tabs {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 14px;
    }}
    .tab {{
      border: 1px solid var(--border);
      background: var(--panel-alt);
      color: var(--text);
      border-radius: 999px;
      padding: 10px 14px;
      cursor: pointer;
    }}
    .tab.active {{
      border-color: var(--accent);
      color: white;
      background: rgba(110, 168, 254, .18);
    }}
    .toolbar {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      margin-bottom: 16px;
    }}
    .toolbar-actions {{
      display: flex;
      flex-wrap: nowrap;
      gap: 8px;
      align-items: center;
      margin-left: auto;
    }}
    .toolbar-switch {{
      display: inline-flex;
      gap: 4px;
      padding: 3px;
      border: 1px solid var(--border);
      border-radius: 999px;
      background: var(--panel-alt);
      flex: 0 0 auto;
    }}
    .toolbar-switch button {{
      border: 0;
      background: transparent;
      color: var(--muted);
      border-radius: 999px;
      padding: 6px 10px;
      cursor: pointer;
      font: inherit;
      font-size: 12px;
      line-height: 1.1;
    }}
    .toolbar-switch button.active {{
      background: rgba(110, 168, 254, .18);
      color: var(--text);
    }}
    input[type="search"] {{
      width: 360px;
      max-width: 100%;
      background: #0d1430;
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px 12px;
    }}
    @media (max-width: 980px) {{
      .toolbar-actions {{
        flex-wrap: wrap;
        width: 100%;
        margin-left: 0;
      }}
      input[type="search"] {{
        width: min(360px, 100%);
      }}
    }}
    #table-container {{
      overflow-x: auto;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    th, td {{
      padding: 10px 12px;
      border-top: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-weight: 600;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .06em;
    }}
    tr:hover td {{
      background: rgba(255,255,255,.02);
    }}
    .pill {{
      display: inline-block;
      border-radius: 999px;
      padding: 4px 8px;
      font-size: 12px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,.04);
    }}
    .pill.critical {{ color: #ffb3b3; }}
    .pill.noncritical {{ color: #f2cc60; }}
    .pill.match {{ color: #8ddb8c; }}
    .pill.mismatch {{ color: #f2cc60; }}
    .pill.missing {{ color: var(--muted); }}
    .reason {{
      color: var(--muted);
      max-width: 420px;
    }}
    .message-column {{
      min-width: 260px;
      width: 260px;
      max-width: 260px;
    }}
    .message-text {{
      display: block;
      max-width: 260px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .stack-list {{
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}
    .comparison-value {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }}
    .status-indicator {{
      font-size: 12px;
      font-weight: 700;
      line-height: 1;
    }}
    .status-indicator.match {{
      color: #8ddb8c;
    }}
    .status-indicator.mismatch,
    .status-indicator.missing {{
      color: #f85149;
    }}
    .score-column {{
      width: 1%;
      white-space: nowrap;
      text-align: right;
    }}
    .score-box {{
      color: var(--muted);
      font-size: 12px;
      margin-top: 6px;
    }}
    .score-total {{
      color: var(--text);
      font-weight: 700;
      margin-bottom: 0;
    }}
    .score-inline {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      white-space: nowrap;
    }}
    .reason-button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 24px;
      height: 24px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: var(--panel-alt);
      color: var(--accent);
      cursor: pointer;
      font-size: 13px;
      font-weight: 700;
    }}
    .details-button {{
      font-size: 13px;
      letter-spacing: 0;
    }}
    .details-column {{
      width: 1%;
      white-space: nowrap;
      text-align: right;
    }}
    .id-row td {{
      padding-top: 0;
      color: var(--muted);
      font-size: 12px;
      border-top: 0;
    }}
    .id-strip {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
    }}
    .id-right {{
      text-align: right;
    }}
    .issue-banner {{
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 16px;
      color: #f2cc60;
    }}
    .issue-icon {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 18px;
      height: 18px;
      border-radius: 999px;
      background: rgba(242, 204, 96, .18);
      border: 1px solid rgba(242, 204, 96, .45);
      color: #f2cc60;
      font-size: 12px;
      font-weight: 700;
      flex: 0 0 auto;
    }}
    .reason-modal {{
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(0, 0, 0, .65);
      padding: 24px;
      z-index: 1000;
    }}
    .reason-modal.open {{
      display: flex;
    }}
    .reason-modal-card {{
      width: min(720px, 100%);
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 18px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, .35);
    }}
    .reason-modal-head {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      margin-bottom: 12px;
    }}
    .reason-modal-close {{
      border: 1px solid var(--border);
      background: var(--panel-alt);
      color: var(--text);
      border-radius: 10px;
      padding: 8px 12px;
      cursor: pointer;
    }}
    details {{
      margin: 0;
    }}
    summary {{
      cursor: pointer;
      color: var(--accent);
    }}
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      background: #0d1430;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px;
      max-height: 400px;
      overflow: auto;
    }}
    .header-row {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: flex-start;
    }}
    .link-button {{
      display: inline-block;
      color: var(--text);
      text-decoration: none;
      border: 1px solid var(--border);
      background: var(--panel-alt);
      border-radius: 999px;
      padding: 10px 14px;
      white-space: nowrap;
    }}
    @media (max-width: 1380px) {{
      .summary-cards {{
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <section class="hero">
      <div class="header-row">
        <div>
          <h1>Event comparison browser</h1>
          <div class="subtle">Browse Truesight critical-event comparison results against BHOM.</div>
        </div>
        <div style="display:flex; gap:10px; flex-wrap:wrap;">
          <a class="link-button" href="statistics.html">Statistics</a>
          <a class="link-button" href="mapping_documentation.html">Mapping documentation</a>
          <a class="link-button" href="matching_documentation.html">Matching documentation</a>
        </div>
      </div>
      <div class="meta-grid">
        <div class="meta-card">
          <strong>Truesight analysed</strong>
          <div class="subtle">Events: {truesight_meta.get('analyzed_event_count', truesight_meta.get('event_count', '-'))}</div>
          <div class="subtle">Start: {escape(format_header_timestamp(str(truesight_meta.get('start_time', ''))))}</div>
          <div class="subtle">End: {escape(format_header_timestamp(str(truesight_meta.get('end_time', ''))))}</div>
        </div>
        <div class="meta-card">
          <strong>BHOM analysed</strong>
          <div class="subtle">Events: {bhom_meta.get('analyzed_event_count', bhom_meta.get('event_count', '-'))}</div>
          <div class="subtle">Start: {escape(format_header_timestamp(str(bhom_meta.get('start_time', ''))))}</div>
          <div class="subtle">End: {escape(format_header_timestamp(str(bhom_meta.get('end_time', ''))))}</div>
        </div>
      </div>
      <div class="cards summary-cards">
        <div class="card"><div class="label">Truesight critical</div><div class="value">{ts_summary['critical_events_in_truesight']}</div></div>
        <div class="card"><div class="label">Matched to BHOM</div><div class="value">{ts_summary['matched_count']}</div><div class="meta">{coverage_percent(ts_summary['matched_count'], critical_total)} coverage</div></div>
        <div class="card"><div class="label">Severity mismatch</div><div class="value">{ts_summary['matched_to_noncritical_count']}</div><div class="meta">{severity_alignment_coverage} coverage</div></div>
        <div class="card"><div class="label">Responsibility mismatch</div><div class="value">{payload['responsibility_mismatch_count']}</div><div class="meta">{responsibility_alignment_coverage} coverage</div></div>
        <div class="card"><div class="label">Notification mismatch</div><div class="value">{payload['notification_mismatch_count']}</div><div class="meta">{notification_alignment_coverage} coverage</div></div>
        <div class="card"><div class="label">Ambiguous</div><div class="value">{ts_summary['ambiguous_count']}</div></div>
        <div class="card"><div class="label">No BHOM candidate</div><div class="value">{ts_summary['unmatched_count']}</div></div>
        <div class="card"><div class="label">Overall coverage</div><div class="value">{overall_coverage}</div></div>
      </div>
      {"".join(f'<div class="issue-banner"><span class="issue-icon">!</span><span>{escape(note)}</span></div>' for note in issue_notes)}
    </section>

    <section class="panel">
      <div class="tabs" id="tabs"></div>
      <div class="toolbar">
        <div>
          <div id="section-description" class="subtle"></div>
          <div id="section-count" class="subtle" style="margin-top:4px;"></div>
        </div>
        <div class="toolbar-actions">
          <input id="search" type="search" placeholder="Search event id, object, host, message, severity...">
          <div id="matched-filter" class="toolbar-switch" hidden>
            <button id="matched-filter-all" type="button" class="active">All lines</button>
            <button id="matched-filter-mismatch" type="button">Only mismatches</button>
          </div>
        </div>
      </div>
      <div id="table-container"></div>
    </section>
  </div>

  <div id="reason-modal" class="reason-modal" aria-hidden="true">
    <div class="reason-modal-card">
      <div class="reason-modal-head">
        <strong id="reason-modal-title">Reason</strong>
        <button id="reason-modal-close" class="reason-modal-close" type="button">Close</button>
      </div>
      <pre id="reason-modal-body"></pre>
    </div>
  </div>

  <script>
    const reportData = {data_json};
    const state = {{ activeSectionId: reportData.sections[0].id, search: "", matchedFilter: "all" }};
    const reasonModal = document.getElementById("reason-modal");
    const reasonModalTitle = document.getElementById("reason-modal-title");
    const reasonModalBody = document.getElementById("reason-modal-body");
    const reasonModalClose = document.getElementById("reason-modal-close");
    const matchedFilter = document.getElementById("matched-filter");
    const matchedFilterAll = document.getElementById("matched-filter-all");
    const matchedFilterMismatch = document.getElementById("matched-filter-mismatch");

    function sectionById(id) {{
      return reportData.sections.find(section => section.id === id);
    }}

    function renderTabs() {{
      const tabs = document.getElementById("tabs");
      tabs.innerHTML = "";
      for (const section of reportData.sections) {{
        const button = document.createElement("button");
        button.className = "tab" + (section.id === state.activeSectionId ? " active" : "");
        button.textContent = `${{section.label}} (${{section.rows.length}})`;
        button.onclick = () => {{
          state.activeSectionId = section.id;
          render();
        }};
        tabs.appendChild(button);
      }}
    }}

    function filteredRows(section) {{
      let rows = section.rows;
      if (section.id === "matched" && state.matchedFilter === "mismatch") {{
        rows = rows.filter(hasMismatch);
      }}
      const query = state.search.trim().toLowerCase();
      if (!query) return rows;
      return rows.filter(row => row.search_text.includes(query));
    }}

    function hasMismatch(row) {{
      return row.severity_alignment !== "critical"
        || row.responsibility_alignment !== "match"
        || row.notification_alignment !== "match";
    }}

    function renderToolbarControls(section) {{
      const showMatchedFilter = section.id === "matched";
      matchedFilter.hidden = !showMatchedFilter;
      matchedFilter.style.display = showMatchedFilter ? "inline-flex" : "none";
      if (!showMatchedFilter) return;
      matchedFilterAll.classList.toggle("active", state.matchedFilter === "all");
      matchedFilterMismatch.classList.toggle("active", state.matchedFilter === "mismatch");
    }}

    function renderTable() {{
      const section = sectionById(state.activeSectionId);
      renderToolbarControls(section);
      const rows = filteredRows(section);
      document.getElementById("section-description").textContent = section.description;
      document.getElementById("section-count").textContent = `${{rows.length}} shown of ${{section.rows.length}}`;

      const tableContainer = document.getElementById("table-container");
      const table = document.createElement("table");
      const columnConfig = (() => {{
        switch (section.id) {{
          case "matched":
            return {{
              comparisonColumns: [
                "Truesight severity",
                "BHOM severity",
                "Truesight responsibility",
                "BHOM responsibility",
                "Expected notification type",
                "BHOM notification type",
              ],
            }};
          case "responsibility-mismatch":
            return {{
              comparisonColumns: [
                "Truesight responsibility",
                "BHOM responsibility",
              ],
            }};
          case "notification-mismatch":
            return {{
              comparisonColumns: [
                "Expected notification type",
                "BHOM notification type",
              ],
            }};
          case "ambiguous":
            return {{
              comparisonColumns: [
                "Truesight severity",
                "Identifier",
              ],
            }};
          default:
            return {{
              comparisonColumns: [
                "Truesight severity",
                "BHOM severity",
              ],
            }};
        }}
      }})();
      const columnCount = 2 + columnConfig.comparisonColumns.length + 2;
      table.innerHTML = `
        <thead>
          <tr>
            <th>Host</th>
            <th class="message-column">Message</th>
            ${{columnConfig.comparisonColumns.map(header => `<th>${{header}}</th>`).join("")}}
            <th class="score-column">Score</th>
            <th class="details-column"></th>
          </tr>
        </thead>
      `;
      const tbody = document.createElement("tbody");

      for (const row of rows) {{
        const tr = document.createElement("tr");
        const renderStack = (value) => Array.isArray(value)
          ? `<div class="stack-list">${{value.map(item => `<div>${{escapeHtml(item || "-")}}</div>`).join("")}}</div>`
          : escapeHtml(value || "-");
        const renderStatusWithIndicator = (value, alignment) => {{
          const statusClass = alignment === "match" ? "match" : "mismatch";
          const statusIcon = alignment === "match" ? "&#10003;" : "&#10005;";
          return `<span class="comparison-value">${{value}}<span class="status-indicator ${{statusClass}}">${{statusIcon}}</span></span>`;
        }};
        const bhomSeverityValue = row.kind === "matched"
          ? `<span class="pill ${{row.bhom_severity === "CRITICAL" ? "critical" : "noncritical"}}">${{row.bhom_severity || "-"}}</span>`
          : renderStack(row.bhom_severity);
        const truesightSeverityValue = `<span class="pill critical">${{escapeHtml(row.truesight_severity || "-")}}</span>`;
        const comparisonCells = (() => {{
          switch (section.id) {{
            case "matched":
              return [
                truesightSeverityValue,
                renderStatusWithIndicator(bhomSeverityValue, row.severity_alignment === "critical" ? "match" : "mismatch"),
                escapeHtml(row.truesight_responsibility || "-"),
                renderStatusWithIndicator(escapeHtml(row.bhom_responsibility || "-"), row.responsibility_alignment),
                escapeHtml(row.truesight_notification_type || "-"),
                renderStatusWithIndicator(escapeHtml(row.bhom_notification_type || "-"), row.notification_alignment),
              ];
            case "responsibility-mismatch":
              return [
                escapeHtml(row.truesight_responsibility || "-"),
                escapeHtml(row.bhom_responsibility || "-"),
              ];
            case "notification-mismatch":
              return [
                escapeHtml(row.truesight_notification_type || "-"),
                escapeHtml(row.bhom_notification_type || "-"),
              ];
            default:
              return [
                truesightSeverityValue,
                bhomSeverityValue,
              ];
          }}
        }})();
        const reasonText = formatReason(row);
        const scoreOrReason = row.kind === "matched"
          ? `
              <div class="score-inline">
                <div class="score-total">${{escapeHtml(row.score)}}</div>
                <button type="button" class="reason-button" title="Open reason" aria-label="Open reason">?</button>
              </div>
            `
          : `<button type="button" class="reason-button" title="Open reason" aria-label="Open reason">?</button>`;

        tr.innerHTML = `
          <td>${{escapeHtml(row.host || "-")}}</td>
          <td class="message-column"><span class="message-text" title="${{escapeHtml(row.message || "-")}}">${{escapeHtml(row.message || "-")}}</span></td>
          ${{comparisonCells.map(value => `<td>${{value}}</td>`).join("")}}
          <td class="reason score-column">${{scoreOrReason}}</td>
          <td class="details-column">
            <button type="button" class="reason-button details-button" title="Open details" aria-label="Open details">i</button>
          </td>
        `;
        const reasonButton = tr.querySelector(".reason-button");
        if (reasonButton) {{
          reasonButton.addEventListener("click", () => openReasonModal("Reason", reasonText));
        }}
        const detailsButton = tr.querySelector(".details-button");
        if (detailsButton) {{
          detailsButton.addEventListener("click", () => openReasonModal("Details", JSON.stringify(row.details, null, 2)));
        }}
        tbody.appendChild(tr);

        const idRow = document.createElement("tr");
        idRow.className = "id-row";
        idRow.innerHTML = `
          <td colspan="${{columnCount}}">
            <div class="id-strip">
              <div>${{escapeHtml(row.truesight_event_id || "-")}}</div>
              <div class="id-right">${{escapeHtml(row.bhom_event_id || "")}}</div>
            </div>
          </td>
        `;
        tbody.appendChild(idRow);
      }}

      table.appendChild(tbody);
      tableContainer.innerHTML = "";
      tableContainer.appendChild(table);
    }}

    function escapeHtml(value) {{
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;");
    }}

    function formatScoreBreakdown(scoreBreakdown) {{
      return Object.entries(scoreBreakdown)
        .map(([key, value]) => `${{key}}: +${{value}}`)
        .join(" | ");
    }}

    function formatReason(row) {{
      if (row.kind === "matched" && row.details.score_breakdown) {{
        return formatScoreBreakdown(row.details.score_breakdown);
      }}
      return row.reason || "-";
    }}

    function openReasonModal(title, text) {{
      reasonModalTitle.textContent = title || "Details";
      reasonModalBody.textContent = text || "-";
      reasonModal.classList.add("open");
      reasonModal.setAttribute("aria-hidden", "false");
    }}

    function closeReasonModal() {{
      reasonModal.classList.remove("open");
      reasonModal.setAttribute("aria-hidden", "true");
      reasonModalTitle.textContent = "Reason";
      reasonModalBody.textContent = "";
    }}

    reasonModalClose.addEventListener("click", closeReasonModal);
    reasonModal.addEventListener("click", (event) => {{
      if (event.target === reasonModal) {{
        closeReasonModal();
      }}
    }});
    document.addEventListener("keydown", (event) => {{
      if (event.key === "Escape" && reasonModal.classList.contains("open")) {{
        closeReasonModal();
      }}
    }});

    function render() {{
      renderTabs();
      renderTable();
    }}

    document.getElementById("search").addEventListener("input", (event) => {{
      state.search = event.target.value;
      renderTable();
    }});
    matchedFilterAll.addEventListener("click", () => {{
      state.matchedFilter = "all";
      renderTable();
    }});
    matchedFilterMismatch.addEventListener("click", () => {{
      state.matchedFilter = "mismatch";
      renderTable();
    }});

    render();
  </script>
</body>
</html>
"""


def render_matching_documentation_html(summary: dict[str, Any]) -> str:
    ts_summary = summary["truesight_to_bhom"]
    bhom_summary = summary["bhom_to_truesight"]
    issues = summary.get("issues", [])
    issue_notes = build_issue_notes(issues, docs_mode=True)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Matching documentation</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg: #0b1020;
      --panel: #121933;
      --panel-alt: #172043;
      --text: #e7ebff;
      --muted: #aab4df;
      --accent: #6ea8fe;
      --border: #2a3668;
    }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    .page {{
      max-width: 1080px;
      margin: 0 auto;
      padding: 24px;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 22px;
      margin-bottom: 18px;
    }}
    h1, h2, h3 {{
      margin-top: 0;
    }}
    p, li {{
      color: var(--text);
      line-height: 1.5;
    }}
    .subtle {{
      color: var(--muted);
    }}
    code {{
      background: #0d1430;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 2px 6px;
    }}
    .link-button {{
      display: inline-block;
      color: var(--text);
      text-decoration: none;
      border: 1px solid var(--border);
      background: var(--panel-alt);
      border-radius: 999px;
      padding: 10px 14px;
      margin-bottom: 12px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
    }}
    .mini {{
      background: var(--panel-alt);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
    }}
  </style>
</head>
<body>
  <div class="page">
    <a class="link-button" href="index.html">Back to results browser</a>

    <section class="panel">
      <h1>Matching documentation</h1>
      <p class="subtle">This page explains how the app decides whether a Truesight event and a BHOM event represent the same underlying event.</p>
      <div class="grid">
        <div class="mini"><strong>Truesight critical events</strong><br>{ts_summary['critical_events_in_truesight']}</div>
        <div class="mini"><strong>Matched to BHOM critical</strong><br>{ts_summary['matched_to_critical_count']}</div>
        <div class="mini"><strong>Matched to BHOM non-critical</strong><br>{ts_summary['matched_to_noncritical_count']}</div>
        <div class="mini"><strong>BHOM critical without Truesight critical</strong><br>{bhom_summary['unmatched_count']}</div>
      </div>
      {"".join(f'<p class="subtle" style="margin-top:16px;">{escape(note)}</p>' for note in issue_notes)}
    </section>

    <section class="panel">
      <h2>1. Normalized event model</h2>
      <p>Before matching, both sources are normalized into a shared internal model. The most important fields are:</p>
      <ul>
        <li><code>object_class</code></li>
        <li><code>object</code> / <code>object_name</code></li>
        <li><code>instance_name</code></li>
        <li><code>parameter_name</code></li>
        <li><code>metric_name</code></li>
        <li><code>host</code></li>
        <li><code>message</code></li>
        <li><code>msg_ident</code> (Truesight)</li>
        <li><code>fingerprint</code> (BHOM <code>six_fingerprint</code> or derived fallback)</li>
        <li><code>creation_time</code></li>
        <li><code>notification_group</code></li>
        <li><code>severity</code></li>
      </ul>
      <p>For Truesight, the BAROC export is used directly, so slots like <code>p_instance</code>, <code>mc_parameter</code>, <code>msg_ident</code>, <code>resp</code>, and <code>resp_type</code> are read from the source instead of reconstructed from JSON. The shared <code>notification_group</code> field is what the UI shows as responsibility: Truesight <code>resp</code> versus BHOM <code>six_notification_group</code>. The shared <code>notification_type</code> field compares BHOM <code>six_notification_type</code> with the expected Truesight notification type derived from <code>alarm_type</code>, <code>resp_type</code>, and <code>with_ars</code>.</p>
    </section>

    <section class="panel">
      <h2>2. Candidate collection</h2>
      <p>The matcher first builds a candidate set from stronger identity keys. BHOM candidates are collected when one or more of these keys overlap:</p>
      <ol>
        <li><code>fingerprint</code></li>
        <li><code>object_class + object + host</code></li>
        <li><code>object_class + instance + host</code></li>
        <li><code>object_class + object</code></li>
        <li><code>object + host</code></li>
        <li><code>object_class + host</code></li>
        <li><code>object</code> only</li>
        <li><code>msg_ident + host</code></li>
      </ol>
      <p>If these key-based lookups do not produce a strong enough candidate, the matcher performs a conservative fallback search using <strong>message similarity + creation time</strong>.</p>
    </section>

    <section class="panel">
      <h2>3. Scoring</h2>
      <p>Each candidate receives a score. Stronger identity signals contribute more than weaker contextual signals.</p>
      <ul>
        <li><strong>High-weight identity signals:</strong> object class, object, instance, fingerprint, msg_ident</li>
        <li><strong>Context signals:</strong> host, metric name, notification group</li>
        <li><strong>Time signals:</strong> creation times closer together score higher</li>
        <li><strong>Message signals:</strong> exact normalized message signature or high similarity</li>
      </ul>
      <p>A candidate becomes a direct match only if its score clears the minimum threshold and there is no near-tie with another candidate.</p>
    </section>

    <section class="panel">
      <h2>3a. Current score weights and thresholds</h2>
      <p>The current implementation uses these point values:</p>
      <ul>
        <li><code>object_class</code> match: <strong>+35</strong></li>
        <li><code>object</code> match: <strong>+35</strong></li>
        <li><code>fingerprint</code> match: <strong>+28</strong></li>
        <li><code>instance</code> match: <strong>+25</strong></li>
        <li><code>msg_ident</code> match: <strong>+22</strong></li>
        <li><code>host</code> match: <strong>+20</strong></li>
        <li><code>metric_name</code> match: <strong>+18</strong></li>
        <li><code>message_time_fallback</code>: <strong>+18</strong> or <strong>+12</strong></li>
        <li><code>object_to_instance</code>: <strong>+14</strong></li>
        <li>time delta <code>&lt;= 5 min</code>: <strong>+12</strong></li>
        <li>exact normalized message signature: <strong>+10</strong></li>
        <li>time delta <code>&lt;= 1 hour</code>: <strong>+8</strong></li>
        <li>message similarity <code>&gt;= 0.9</code>: <strong>+8</strong></li>
        <li>time delta <code>&lt;= 3 hours</code>: <strong>+5</strong></li>
        <li>message similarity <code>&gt;= 0.75</code>: <strong>+5</strong></li>
        <li><code>notification_group</code> match: <strong>+4</strong></li>
        <li><code>severity</code> match: <strong>+3</strong></li>
      </ul>
      <p>Confidence labels are assigned after the total score is calculated:</p>
      <ul>
        <li><strong>high</strong>: score <code>&gt;= 95</code></li>
        <li><strong>medium</strong>: score <code>&gt;= 70</code></li>
        <li><strong>low</strong>: score below <code>70</code></li>
      </ul>
      <p>A candidate becomes a direct match only if the best candidate reaches at least <code>55</code> points.</p>
    </section>

    <section class="panel">
      <h2>4. Time and message fallback</h2>
      <p>When key-based matching is weak or missing, the matcher can still propose candidates if:</p>
      <ul>
        <li>the message signatures are identical and the host matches, or</li>
        <li>the host and object class match and the message similarity is very high,</li>
      </ul>
      <p>and the creation times are within a limited time window.</p>
      <p>This fallback is also used to break ties between repeated BHOM events: if two candidates are otherwise very similar, the one that is materially closer in time is preferred.</p>
    </section>

    <section class="panel">
      <h2>4a. When a case becomes ambiguous</h2>
      <p>A case is marked as ambiguous instead of matched when the top two candidates remain too close after scoring. In the current implementation, ambiguity is triggered when:</p>
      <ul>
        <li>the score gap between the best and second-best candidate is <code>&lt;= 2</code>,</li>
        <li>the message similarity gap is below <code>0.03</code>, and</li>
        <li>the second candidate is not more than <code>10 minutes</code> worse in creation-time distance.</li>
      </ul>
      <p>In other words, if two candidates still look almost equally good, the app prefers to surface them for review instead of pretending the choice is certain.</p>
    </section>

    <section class="panel">
      <h2>5. Result categories</h2>
      <ul>
        <li><strong>Matched</strong>: same event found and BHOM is also critical</li>
        <li><strong>Severity mismatch</strong>: same event found, but BHOM is not critical</li>
        <li><strong>Ambiguous</strong>: multiple BHOM candidates remain plausible</li>
        <li><strong>No BHOM candidate</strong>: no candidate in the current BHOM sample reached the minimum threshold</li>
      </ul>
      <p>The reverse analysis uses the same logic in the other direction to find BHOM critical events that have no Truesight critical counterpart. In the browser UI, accepted matches also show a responsibility comparison based on Truesight <code>resp</code> and BHOM <code>six_notification_group</code>, including a dedicated responsibility-mismatch view.</p>
    </section>

    <section class="panel">
      <h2>6. Important limitations</h2>
      <ul>
        <li>The BHOM file used here is a partial sample, so “unmatched” does not always mean “missing in BHOM.”</li>
        <li><code>msg_ident</code> and <code>fingerprint</code> are both used, but the current logic does <strong>not</strong> directly compare Truesight <code>msg_ident</code> to BHOM <code>six_fingerprint</code> as a dedicated rule.</li>
        <li>Repeated or deduplicated BHOM events can still create ambiguous cases.</li>
      </ul>
    </section>
  </div>
</body>
</html>
"""


def render_mapping_documentation_html(summary: dict[str, Any]) -> str:
    issue_notes = build_issue_notes(summary.get("issues", []), docs_mode=True)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mapping documentation</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg: #0b1020;
      --panel: #121933;
      --panel-alt: #172043;
      --text: #e7ebff;
      --muted: #aab4df;
      --border: #2a3668;
    }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    .page {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 24px;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 20px;
    }}
    .subtle {{
      color: var(--muted);
    }}
    .link-row {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }}
    .link-button {{
      display: inline-block;
      color: var(--text);
      text-decoration: none;
      border: 1px solid var(--border);
      background: var(--panel-alt);
      border-radius: 999px;
      padding: 10px 14px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
      margin-top: 16px;
    }}
    th, td {{
      padding: 10px 12px;
      border-top: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-weight: 600;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .06em;
    }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      background: rgba(255,255,255,.04);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 2px 6px;
    }}
    ul {{
      margin: 12px 0 0 20px;
    }}
  </style>
</head>
<body>
  <div class="page">
    <div class="link-row">
      <a class="link-button" href="index.html">Back to results browser</a>
    </div>

    <section class="panel">
      <h1>Mapping documentation</h1>
      <p class="subtle">This page explains how Truesight fields are mapped to Helix/BHOM fields for event identification and for the mismatch views in the browser.</p>
      {"".join(f'<p class="subtle">{escape(note)}</p>' for note in issue_notes)}
    </section>

    <section class="panel">
      <h2>1. Event identity mapping</h2>
      <p>The matcher first normalizes both sources into one shared event model. The strongest identity mapping is built from the Truesight quadruple <code>object</code> + <code>object_class</code> + <code>instance</code> + <code>parameter</code>, with BHOM using the equivalent normalized Helix fields.</p>
      <table>
        <thead>
          <tr>
            <th>Canonical meaning</th>
            <th>Truesight source</th>
            <th>Helix / BHOM source</th>
            <th>Notes</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Event ID</td>
            <td><code>mc_ueid</code> (fallback <code>event_handle</code>)</td>
            <td><code>_identifier</code></td>
            <td>Used for reporting, not as the primary cross-source match key.</td>
          </tr>
          <tr>
            <td>Object class</td>
            <td><code>mc_object_class</code></td>
            <td><code>object_class</code></td>
            <td>One of the highest-weight identity signals.</td>
          </tr>
          <tr>
            <td>Object</td>
            <td><code>mc_object</code></td>
            <td><code>object</code></td>
            <td>One of the highest-weight identity signals.</td>
          </tr>
          <tr>
            <td>Instance</td>
            <td><code>p_instance</code></td>
            <td><code>p_instance</code> / <code>instancename</code></td>
            <td>Falls back to object name when the source does not expose a separate instance.</td>
          </tr>
          <tr>
            <td>Parameter / metric</td>
            <td><code>mc_parameter</code></td>
            <td><code>metric_name</code> / <code>al_parameter_name</code></td>
            <td>Truesight parameter and BHOM metric are normalized into the same canonical comparison field.</td>
          </tr>
          <tr>
            <td>Host</td>
            <td><code>mc_host</code></td>
            <td><code>source_hostname</code></td>
            <td>Used directly and also inside the derived fingerprint.</td>
          </tr>
          <tr>
            <td>Message fingerprint</td>
            <td><code>msg_ident</code></td>
            <td><code>six_msg_ident</code> / <code>six_fingerprint</code></td>
            <td>Truesight <code>msg_ident</code> and BHOM fingerprint are normalized separately and used as candidate-collection signals.</td>
          </tr>
          <tr>
            <td>Creation time</td>
            <td><code>mc_incident_time</code></td>
            <td><code>creation_time</code></td>
            <td>Used for fallback matching and tie-breaking, not as a strict equality field.</td>
          </tr>
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h2>2. Field mapping for mismatch detection</h2>
      <p>The mismatch tabs are driven by explicit field mappings after a match is accepted.</p>
      <table>
        <thead>
          <tr>
            <th>Mismatch view</th>
            <th>Truesight field</th>
            <th>Helix / BHOM field</th>
            <th>How it is compared</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Severity mismatch</td>
            <td><code>severity</code></td>
            <td><code>severity</code></td>
            <td>The match is considered severity-aligned only when BHOM remains <code>CRITICAL</code>.</td>
          </tr>
          <tr>
            <td>Responsibility mismatch</td>
            <td><code>resp</code></td>
            <td><code>six_notification_group</code></td>
            <td>Both values are normalized as notification-group strings and then compared directly.</td>
          </tr>
          <tr>
            <td>Notification mismatch</td>
            <td>derived from <code>alarm_type</code>, <code>resp_type</code>, <code>with_ars</code></td>
            <td><code>six_notification_type</code></td>
            <td>Truesight is first converted into an expected notification type, then compared to BHOM. <code>UNDEFINED</code> in BHOM is treated as not set.</td>
          </tr>
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h2>3. Notification-type derivation from Truesight</h2>
      <p>For notification mismatches, Truesight does not use <code>resp_type</code> directly. The expected Helix notification type is derived with these rules:</p>
      <ul>
        <li><code>alarm_type=AUTO</code> + <code>resp_type=PAGER|ALL</code> + <code>with_ars=TRUE</code> -&gt; <code>ONCALL_ITSM</code></li>
        <li><code>alarm_type=AUTO</code> + <code>resp_type=PAGER|ALL</code> -&gt; <code>ONCALL</code></li>
        <li><code>alarm_type=AUTO</code> + <code>resp_type=ITSM</code> -&gt; <code>ITSM</code></li>
        <li><code>alarm_type=AUTO</code> + <code>resp_type=MAIL</code> -&gt; <code>MAIL</code></li>
        <li>otherwise -&gt; empty / not set</li>
      </ul>
    </section>

    <section class="panel">
      <h2>4. How the UI uses the mapping</h2>
      <ul>
        <li>The <strong>Matched</strong> view shows the mapped Truesight and BHOM values side by side.</li>
        <li>The dedicated mismatch tabs show only the mapped fields relevant to that mismatch type.</li>
        <li><strong>Overall coverage</strong> excludes matches where severity, responsibility, or notification mapping does not align.</li>
      </ul>
    </section>
  </div>
</body>
</html>
"""


def render_statistics_html(*, current_snapshot: dict[str, Any], history: list[dict[str, Any]]) -> str:
    pairing_values = [float(item.get("coverage", {}).get("pairing_pct", 0) or 0) for item in history]
    overall_values = [float(item.get("coverage", {}).get("overall_pct", item.get("coverage", {}).get("critical_pct", 0)) or 0) for item in history]
    total_runs = len(history)
    best_pairing = max(pairing_values) if pairing_values else 0.0
    best_overall = max(overall_values) if overall_values else 0.0
    avg_pairing = sum(pairing_values) / total_runs if total_runs else 0.0
    avg_overall = sum(overall_values) / total_runs if total_runs else 0.0
    first_run = history[0].get("run_timestamp", "") if history else ""
    last_run = history[-1].get("run_timestamp", "") if history else ""
    current_ts = current_snapshot.get("truesight_to_bhom", {})
    current_bhom = current_snapshot.get("bhom_to_truesight", {})
    recent_runs = list(reversed(history[-10:]))
    current_dataset = dict(current_snapshot.get("dataset", {}))

    def percent(value: float) -> str:
        return f"{value:.2f}%"

    def value_from(snapshot: dict[str, Any], path: tuple[str, ...], default: str = "-") -> str:
        current: Any = snapshot
        for key in path:
            if not isinstance(current, dict):
                return default
            current = current.get(key)
        if current in (None, ""):
            return default
        return str(current)

    rows_html = "\n".join(
        f"""
          <tr>
             <td>{escape(format_header_timestamp(value_from(run, ("run_timestamp",), "")))}</td>
             <td><code>{escape(value_from(run, ("dataset", "fingerprint"), "-"))}</code></td>
             <td>{escape(value_from(run, ("truesight", "analyzed_event_count")))}</td>
             <td>{escape(value_from(run, ("bhom", "analyzed_event_count")))}</td>
             <td>{escape(value_from(run, ("truesight_to_bhom", "matched_count")))}</td>
            <td>{escape(value_from(run, ("truesight_to_bhom", "ambiguous_count")))}</td>
            <td>{escape(value_from(run, ("truesight_to_bhom", "unmatched_count")))}</td>
            <td>{escape(percent(float(value_from(run, ("coverage", "pairing_pct"), "0"))))}</td>
            <td>{escape(percent(float(value_from(run, ("coverage", "overall_pct"), value_from(run, ("coverage", "critical_pct"), "0")))))}</td>
          </tr>
        """
        for run in recent_runs
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Statistics</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg: #0b1020;
      --panel: #121933;
      --panel-alt: #172043;
      --text: #e7ebff;
      --muted: #aab4df;
      --accent: #6ea8fe;
      --border: #2a3668;
    }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    .page {{
      max-width: 1280px;
      margin: 0 auto;
      padding: 24px;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 20px;
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-top: 18px;
    }}
    .current-run-cards {{
      grid-template-columns: 1.8fr repeat(6, minmax(0, 1fr));
    }}
    .card, .mini {{
      background: var(--panel-alt);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
    }}
    .current-run-cards .card {{
      min-width: 0;
    }}
    .current-run-cards .value {{
      font-size: 24px;
    }}
    .current-run-cards .timestamp-card .value {{
      font-size: 16px;
      white-space: nowrap;
    }}
    .label {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .06em;
    }}
    .value {{
      margin-top: 8px;
      font-size: 28px;
      font-weight: 700;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 12px;
      margin-top: 16px;
    }}
    .subtle {{
      color: var(--muted);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    th, td {{
      padding: 10px 12px;
      border-top: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-weight: 600;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .06em;
    }}
    .link-button {{
      display: inline-block;
      color: var(--text);
      text-decoration: none;
      border: 1px solid var(--border);
      background: var(--panel-alt);
      border-radius: 999px;
      padding: 10px 14px;
      white-space: nowrap;
      margin-bottom: 12px;
    }}
    @media (max-width: 1180px) {{
      .current-run-cards {{
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      }}
      .current-run-cards .timestamp-card .value {{
        white-space: normal;
      }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <a class="link-button" href="index.html">Back to results browser</a>

    <section class="panel">
      <h1>Statistics</h1>
      <p class="subtle">Current run metrics plus summarized history from the snapshots in <code>stats/</code>.</p>
      <div class="cards">
        <div class="card"><div class="label">Runs recorded</div><div class="value">{total_runs}</div></div>
        <div class="card"><div class="label">Best pairing coverage</div><div class="value">{percent(best_pairing)}</div></div>
        <div class="card"><div class="label">Best overall coverage</div><div class="value">{percent(best_overall)}</div></div>
        <div class="card"><div class="label">Average pairing coverage</div><div class="value">{percent(avg_pairing)}</div></div>
        <div class="card"><div class="label">Average overall coverage</div><div class="value">{percent(avg_overall)}</div></div>
      </div>
      <div class="grid">
        <div class="mini"><strong>First run</strong><br><span class="subtle">{escape(format_header_timestamp(first_run))}</span></div>
        <div class="mini"><strong>Latest run</strong><br><span class="subtle">{escape(format_header_timestamp(last_run))}</span></div>
        <div class="mini"><strong>Current dataset</strong><br><span class="subtle"><code>{escape(str(current_dataset.get("fingerprint", "-") or "-"))}</code></span></div>
      </div>
    </section>

    <section class="panel">
      <h2>Current run</h2>
      <div class="cards current-run-cards">
        <div class="card timestamp-card"><div class="label">Run timestamp</div><div class="value">{escape(format_header_timestamp(value_from(current_snapshot, ("run_timestamp",), "")))}</div></div>
        <div class="card"><div class="label">Matched</div><div class="value">{escape(value_from(current_snapshot, ("truesight_to_bhom", "matched_count")))}</div></div>
        <div class="card"><div class="label">Mismatches to check</div><div class="value">{escape(value_from(current_snapshot, ("truesight_to_bhom", "mismatch_count"), "0"))}</div></div>
        <div class="card"><div class="label">Ambiguous</div><div class="value">{escape(value_from(current_snapshot, ("truesight_to_bhom", "ambiguous_count")))}</div></div>
        <div class="card"><div class="label">Unmatched</div><div class="value">{escape(value_from(current_snapshot, ("truesight_to_bhom", "unmatched_count")))}</div></div>
        <div class="card"><div class="label">Pairing coverage</div><div class="value">{percent(float(current_snapshot.get("coverage", {}).get("pairing_pct", 0) or 0))}</div></div>
        <div class="card"><div class="label">Overall coverage</div><div class="value">{percent(float(current_snapshot.get("coverage", {}).get("overall_pct", current_snapshot.get("coverage", {}).get("critical_pct", 0)) or 0))}</div></div>
      </div>
      <div class="grid">
        <div class="mini">
          <strong>Truesight</strong><br>
          <span class="subtle">Events: {escape(value_from(current_snapshot, ("truesight", "analyzed_event_count")))}</span><br>
          <span class="subtle">Critical: {escape(value_from(current_snapshot, ("truesight", "critical_event_count")))}</span><br>
          <span class="subtle">Start: {escape(format_header_timestamp(value_from(current_snapshot, ("truesight", "start_time"), "")))}</span><br>
          <span class="subtle">End: {escape(format_header_timestamp(value_from(current_snapshot, ("truesight", "end_time"), "")))}</span>
        </div>
        <div class="mini">
          <strong>BHOM</strong><br>
          <span class="subtle">Events: {escape(value_from(current_snapshot, ("bhom", "analyzed_event_count")))}</span><br>
          <span class="subtle">Critical: {escape(value_from(current_snapshot, ("bhom_to_truesight", "critical_events_in_bhom")))}</span><br>
          <span class="subtle">Start: {escape(format_header_timestamp(value_from(current_snapshot, ("bhom", "start_time"), "")))}</span><br>
          <span class="subtle">End: {escape(format_header_timestamp(value_from(current_snapshot, ("bhom", "end_time"), "")))}</span>
        </div>
      </div>
    </section>

    <section class="panel">
      <h2>Recent runs</h2>
      <table>
        <thead>
          <tr>
            <th>Run</th>
            <th>Dataset</th>
            <th>Truesight events</th>
            <th>BHOM events</th>
            <th>Matched</th>
            <th>Ambiguous</th>
            <th>Unmatched</th>
            <th>Pairing coverage</th>
            <th>Overall coverage</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </section>
  </div>
</body>
</html>
"""
