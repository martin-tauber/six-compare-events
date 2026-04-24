from __future__ import annotations

import json
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


def coverage_percent(count: int, total: int) -> str:
    return f"{(count / total * 100):.2f}%" if total else "0.00%"


def build_browser_payload(
    *,
    summary: dict[str, Any],
    truesight_to_bhom: dict[str, Any],
) -> dict[str, Any]:
    matched_rows = [flatten_matched_row(row) for row in truesight_to_bhom["matched_to_critical"]]
    severity_mismatch_rows = [flatten_matched_row(row) for row in truesight_to_bhom["matched_to_noncritical"]]
    all_matched_rows = matched_rows + severity_mismatch_rows
    responsibility_mismatch_rows = [row for row in all_matched_rows if row["responsibility_alignment"] == "mismatch"]
    overall_coverage_rows = [row for row in matched_rows if row["responsibility_alignment"] == "match"]

    return {
        "summary": summary,
        "overall_coverage_count": len(overall_coverage_rows),
        "responsibility_mismatch_count": len(responsibility_mismatch_rows),
        "sections": [
            {
                "id": "matched",
                "label": "Matched",
                "description": "Truesight critical events matched to BHOM critical events.",
                "rows": matched_rows,
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
        "title": truesight_event["event_id"],
        "message": truesight_event["message"],
        "host": truesight_event["host"],
        "truesight_severity": truesight_event["severity"],
        "bhom_severity": bhom_event["severity"],
        "truesight_responsibility": truesight_event["notification_group"],
        "bhom_responsibility": bhom_event["notification_group"],
        "responsibility_alignment": row["responsibility_alignment"],
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
            "matched_on": row["matched_on"],
            "message_similarity": row["message_similarity"],
            "time_delta_seconds": row["time_delta_seconds"],
        },
    }


def flatten_ambiguous_row(row: dict[str, Any]) -> dict[str, Any]:
    truesight_event = row["truesight_event"]
    candidates = row["top_candidates"]
    return {
        "kind": "ambiguous",
        "title": truesight_event["event_id"],
        "message": truesight_event["message"],
        "host": truesight_event["host"],
        "truesight_severity": truesight_event["severity"],
        "bhom_severity": ", ".join(candidate["event"]["severity"] for candidate in candidates),
        "truesight_responsibility": truesight_event["notification_group"],
        "bhom_responsibility": ", ".join(candidate["event"]["notification_group"] for candidate in candidates),
        "responsibility_alignment": "",
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
        "title": truesight_event["event_id"],
        "message": truesight_event["message"],
        "host": truesight_event["host"],
        "truesight_severity": truesight_event["severity"],
        "bhom_severity": "",
        "truesight_responsibility": truesight_event["notification_group"],
        "bhom_responsibility": "",
        "responsibility_alignment": "",
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
    issue_note = ""
    issues = payload["summary"].get("issues", [])
    for issue in issues:
        if issue.get("kind") == "partial_export":
            issue_note = (
                f"BHOM export is partial: {issue['materialized_hits']} hits materialized "
                f"while {issue['reported_total']} were reported."
            )
            break

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
    .card {{
      background: var(--panel-alt);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
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
    input[type="search"] {{
      width: min(460px, 100%);
      background: #0d1430;
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px 12px;
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
    .score-column {{
      min-width: 220px;
      width: 220px;
    }}
    .score-box {{
      color: var(--muted);
      font-size: 12px;
      margin-top: 6px;
    }}
    .score-total {{
      color: var(--text);
      font-weight: 700;
      margin-bottom: 4px;
    }}
    .score-toggle {{
      margin-top: 6px;
    }}
    .score-toggle summary {{
      font-size: 12px;
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
        <a class="link-button" href="matching_documentation.html">Matching documentation</a>
      </div>
      <div class="cards">
        <div class="card"><div class="label">Truesight critical</div><div class="value">{ts_summary['critical_events_in_truesight']}</div></div>
        <div class="card"><div class="label">Matched to BHOM</div><div class="value">{ts_summary['matched_count']}</div><div class="meta">{coverage_percent(ts_summary['matched_count'], critical_total)} coverage</div></div>
        <div class="card"><div class="label">Severity mismatch</div><div class="value">{ts_summary['matched_to_noncritical_count']}</div><div class="meta">{severity_alignment_coverage} coverage</div></div>
        <div class="card"><div class="label">Responsibility mismatch</div><div class="value">{payload['responsibility_mismatch_count']}</div><div class="meta">{responsibility_alignment_coverage} coverage</div></div>
        <div class="card"><div class="label">Ambiguous</div><div class="value">{ts_summary['ambiguous_count']}</div></div>
        <div class="card"><div class="label">No BHOM candidate</div><div class="value">{ts_summary['unmatched_count']}</div></div>
        <div class="card"><div class="label">Overall coverage</div><div class="value">{overall_coverage}</div></div>
      </div>
      <p class="subtle" style="margin:16px 0 0;">{escape(issue_note) if issue_note else ''}</p>
    </section>

    <section class="panel">
      <div class="tabs" id="tabs"></div>
      <div class="toolbar">
        <div>
          <div id="section-description" class="subtle"></div>
          <div id="section-count" class="subtle" style="margin-top:4px;"></div>
        </div>
        <input id="search" type="search" placeholder="Search event id, object, host, message, severity...">
      </div>
      <div id="table-container"></div>
    </section>
  </div>

  <script>
    const reportData = {data_json};
    const state = {{ activeSectionId: reportData.sections[0].id, search: "" }};

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
      const query = state.search.trim().toLowerCase();
      if (!query) return section.rows;
      return section.rows.filter(row => row.search_text.includes(query));
    }}

    function renderTable() {{
      const section = sectionById(state.activeSectionId);
      const rows = filteredRows(section);
      document.getElementById("section-description").textContent = section.description;
      document.getElementById("section-count").textContent = `${{rows.length}} shown of ${{section.rows.length}}`;

      const tableContainer = document.getElementById("table-container");
      const table = document.createElement("table");
      table.innerHTML = `
        <thead>
          <tr>
            <th>Event</th>
            <th>Host</th>
            <th class="message-column">Message</th>
            <th>Truesight severity</th>
            <th>BHOM severity</th>
            <th>Truesight resp</th>
            <th>BHOM resp</th>
            <th>Responsibility</th>
            <th class="score-column">Score / reason</th>
            <th>Details</th>
          </tr>
        </thead>
      `;
      const tbody = document.createElement("tbody");

      for (const row of rows) {{
        const tr = document.createElement("tr");
        const severityAlignment = row.kind === "matched"
          ? `<span class="pill ${{row.bhom_severity === "CRITICAL" ? "critical" : "noncritical"}}">${{row.bhom_severity || "-"}}</span>`
          : row.bhom_severity || "-";
        const responsibilityAlignment = row.kind === "matched"
          ? `<span class="pill ${{row.responsibility_alignment}}">${{escapeHtml(row.responsibility_alignment || "-")}}</span>`
          : escapeHtml(row.responsibility_alignment || "-");
        const scoreOrReason = row.kind === "matched"
          ? `
              <div class="score-total">${{escapeHtml(row.score)}}</div>
              ${{row.details.score_breakdown ? `
                <details class="score-toggle">
                  <summary>Reason</summary>
                  <div class="score-box">${{escapeHtml(formatScoreBreakdown(row.details.score_breakdown))}}</div>
                </details>
              ` : ""}}
            `
          : `${{escapeHtml(row.reason || "-")}}`;

        tr.innerHTML = `
          <td>${{escapeHtml(row.title)}}</td>
          <td>${{escapeHtml(row.host || "-")}}</td>
          <td class="message-column"><span class="message-text" title="${{escapeHtml(row.message || "-")}}">${{escapeHtml(row.message || "-")}}</span></td>
          <td><span class="pill critical">${{escapeHtml(row.truesight_severity || "-")}}</span></td>
          <td>${{severityAlignment}}</td>
          <td>${{escapeHtml(row.truesight_responsibility || "-")}}</td>
          <td>${{escapeHtml(row.bhom_responsibility || "-")}}</td>
          <td>${{responsibilityAlignment}}</td>
          <td class="reason score-column">${{scoreOrReason}}</td>
          <td>
            <details>
              <summary>Open</summary>
              <pre>${{escapeHtml(JSON.stringify(row.details, null, 2))}}</pre>
            </details>
          </td>
        `;
        tbody.appendChild(tr);
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

    function render() {{
      renderTabs();
      renderTable();
    }}

    document.getElementById("search").addEventListener("input", (event) => {{
      state.search = event.target.value;
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
    issue_note = ""
    for issue in issues:
        if issue.get("kind") == "partial_export":
            issue_note = (
                f"Current BHOM sample is partial: {issue['materialized_hits']} hits are present in the file "
                f"while {issue['reported_total']} were reported by the export."
            )
            break

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
      <p class="subtle" style="margin-top:16px;">{escape(issue_note) if issue_note else ''}</p>
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
      <p>For Truesight, the BAROC export is used directly, so slots like <code>p_instance</code>, <code>mc_parameter</code>, <code>msg_ident</code>, <code>resp</code>, and <code>resp_type</code> are read from the source instead of reconstructed from JSON. The shared <code>notification_group</code> field is what the UI shows as responsibility: Truesight <code>resp</code> versus BHOM <code>six_notification_group</code>.</p>
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
