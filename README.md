# Shadow AI Scanner — Demo + CLI

This repository contains:

- **Web Demo (static)**: `index.html`
  - Runs **100% client-side** (no uploads)
  - Detects common Shadow AI risk signals (exposed keys, AI libraries, hardcoded prompts)
  - Export report as **Markdown** or **JSON**

- **CLI Scanner (Python)**: `scanner.py`
  - Scans a local directory for Shadow AI indicators
  - Outputs console report, JSON, or a professional Markdown report

## Web Demo

### Vercel
This repo is configured for Vercel as a static site via `vercel.json`.

### Demo dataset
- Download: `demo-dataset.zip` (contains fake keys for safe demo)

### Sample report
- `sample-report.md`

## CLI Scanner

```bash
python3 scanner.py .
python3 scanner.py . --json
python3 scanner.py . --md --output report.md
```

## Notes
- Any detected secrets are **masked** in output.
- This is a demo scaffold; extend patterns + CI integration for production use.
