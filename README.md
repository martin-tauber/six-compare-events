# evdiff

`evdiff` compares Truesight and BHOM event dumps and reports how well critical events match between both systems, including field-level mismatch checks for severity, responsibility, and notification behavior.

## Project layout

- `evdiff.py` - CLI entrypoint
- `lib/` - loaders, matching logic, and report generation
- `input/` - source dump files
- `output/` - generated reports
- `stats/` - generated statistics snapshots for trend analysis
- `tests/` - unit tests

## Input files

Current workflow expects:

- a Truesight BAROC dump
- a BHOM JSON dump
- optionally, a CSV exception file for Truesight exclusions
- optionally, a CSV filter file for BHOM exclusions

Example files in `input/`:

- `input/truesight_20260423110000-20260423120000.baroc`
- `input/BHOM_20260423110000-20260423120000.json`

## Run the tool

```bash
python3 evdiff.py \
  --truesight input/truesight_20260423110000-20260423120000.baroc \
  --bhom input/BHOM_20260423110000-20260423120000.json
```

With an exception file:

```bash
python3 evdiff.py \
  --truesight input/truesight_20260423110000-20260423120000.baroc \
  --bhom input/bhom.jsonl \
  --exceptions input/exceptions.csv
```

With Truesight and BHOM filter files:

```bash
python3 evdiff.py \
  --truesight input/truesight_20260423110000-20260423120000.baroc \
  --bhom input/bhom.jsonl \
  --exceptions input/exceptions.csv \
  --bhom-exceptions input/bhom-exceptions.csv
```

You can override the output directory:

```bash
python3 evdiff.py \
  --truesight input/truesight_20260423110000-20260423120000.baroc \
  --bhom input/BHOM_20260423110000-20260423120000.json \
  --output-dir output
```

You can also override the statistics directory:

```bash
python3 evdiff.py \
  --truesight input/truesight_20260423110000-20260423120000.baroc \
  --bhom input/BHOM_20260423110000-20260423120000.json \
  --output-dir output \
  --stats-dir stats
```

## Generated output

Main files written to `output/`:

- `index.html` - browser view of matched, severity, responsibility, notification, ambiguous, and unmatched events
- `statistics.html` - current run stats plus summarized history from the configured stats directory
- `mapping_documentation.html` - Truesight to Helix/BHOM field mapping used for mismatch checks
- `matching_documentation.html` - explanation of the matching and scoring logic
- `summary.json` - overall metrics
- `ingestion_issues.json` - warnings such as partial BHOM exports or analysis-window clamping
- `matched_critical_events.json` / `.csv`
- `matched_critical_to_critical.json`
- `matched_critical_to_noncritical.json` / `.csv`
- `ambiguous_critical_events.json` / `.csv`
- `unmatched_critical_events.json` / `.csv`
- `filtered_truesight_events.json` / `.csv`
- `filtered_bhom_events.json` / `.csv`
- reverse BHOM-to-Truesight result files

Statistics snapshots are also written to the configured stats directory (`stats/` by default):

- `latest.json` - most recent run
- `history.jsonl` - one JSON record per unique input dataset fingerprint
- `stats_<dataset_fingerprint>.json` - snapshot for a specific input dataset, overwritten when the same inputs are run again

Each snapshot includes a dataset fingerprint derived from the two input files so rerunning the same dataset updates the existing stats entry instead of appending a duplicate run.

Open the browser report directly in your browser:

```bash
open output/index.html
```

## What the tool does

The current implementation focuses on critical-event comparison:

1. Load and normalize Truesight and BHOM events
2. Optionally exclude Truesight events and BHOM events that match filter rules
3. Limit the analyzed event set to the shared time window when the Truesight and BHOM sample ranges differ
4. Keep candidate search on the full opposite source so time-clamped analysis can still match events outside the overlap when the scoring logic supports it
5. Match Truesight critical events to BHOM events
6. Split results into:
   - matched to BHOM critical
   - matched to BHOM non-critical
   - ambiguous
   - unmatched
7. Run the reverse view for BHOM critical events
8. Compare responsibility and notification type alignment for accepted matches
9. Generate HTML, JSON, and CSV outputs

The browser report includes:

- a matched view with all accepted matches and an inline mismatch-only switch
- dedicated severity, responsibility, and notification mismatch views
- warning banners for partial BHOM exports and analysis-window clamping
- a statistics page with current-run metrics, historical summaries, and dataset fingerprints

Matching uses a weighted score based on signals such as object class, canonical instance, host, fingerprint, parameter/metric, message similarity, and time proximity.

## Notes

- Truesight input should be BAROC.
- BHOM input can be either the wrapped export JSON used in this project or line-delimited JSON (`.jsonl`) with one event or hit document per line.
- Truesight `stage` is normalized from `prod_category`.
- Truesight exceptions and BHOM filters use the same CSV format: `stage`, `severity`, `host`, `object class`, `instance`, `parameter`, `msg`, `reason`; a header row is optional. The trailing `reason` field acts like a comment and is not used for matching. Populated match cells are treated as regex filters, and both blank cells and a literal `*` behave like wildcards (`.*`).
- For notification comparison, Truesight notification type is derived from `alarm_type`, `resp_type`, and `with_ars`, then compared to BHOM `six_notification_type`.
- `output/`, `input/`, and `stats/` are ignored by Git in this repository.

## Tests

Run the test suite with:

```bash
python3 -m unittest discover -s tests -v
```
