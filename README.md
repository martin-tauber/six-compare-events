# evdiff

`evdiff` compares Truesight and BHOM event dumps and reports how well critical events match between both systems.

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

Example files in `input/`:

- `input/truesight_20260423110000-20260423120000.baroc`
- `input/BHOM_20260423110000-20260423120000.json`

## Run the tool

```bash
python3 evdiff.py \
  --truesight input/truesight_20260423110000-20260423120000.baroc \
  --bhom input/BHOM_20260423110000-20260423120000.json
```

You can override the output directory:

```bash
python3 evdiff.py \
  --truesight input/truesight_20260423110000-20260423120000.baroc \
  --bhom input/BHOM_20260423110000-20260423120000.json \
  --output-dir output
```

## Generated output

Main files written to `output/`:

- `index.html` - browser view of matched, severity, responsibility, notification, ambiguous, and unmatched events
- `statistics.html` - current run stats plus summarized history from `stats/`
- `matching_documentation.html` - explanation of the matching and scoring logic
- `summary.json` - overall metrics
- `matched_critical_events.json` / `.csv`
- `matched_critical_to_critical.json`
- `matched_critical_to_noncritical.json` / `.csv`
- `ambiguous_critical_events.json` / `.csv`
- `unmatched_critical_events.json` / `.csv`
- reverse BHOM-to-Truesight result files

Statistics snapshots are also written to `stats/`:

- `latest.json` - most recent run
- `history.jsonl` - one JSON record per unique input dataset fingerprint
- `stats_<dataset_fingerprint>.json` - snapshot for a specific input dataset, overwritten when the same inputs are run again

Open the browser report directly in your browser:

```bash
open output/index.html
```

## What the tool does

The current implementation focuses on critical-event comparison:

1. Load and normalize Truesight and BHOM events
2. Limit analysis to the shared time window when the Truesight and BHOM sample ranges differ
3. Match Truesight critical events to BHOM events
4. Split results into:
   - matched to BHOM critical
   - matched to BHOM non-critical
   - ambiguous
   - unmatched
5. Run the reverse view for BHOM critical events
6. Compare responsibility and notification type alignment for accepted matches
7. Generate HTML, JSON, and CSV outputs

Matching uses a weighted score based on signals such as object class, object, instance, host, fingerprint, `msg_ident`, metric name, message similarity, and time proximity.

## Notes

- Truesight input should be BAROC.
- BHOM input is expected as the exported JSON dump currently used in this project.
- `output/`, `input/`, and `stats/` are ignored by Git in this repository.

## Tests

Run the test suite with:

```bash
python3 -m unittest discover -s tests -v
```
