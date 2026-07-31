# Development

## :material-folder-cog-outline: Repository Layout

```text
project-root/
├── app.py
├── boogr.py
├── config.py
├── mkdocs.yml
├── docs/
│   ├── api/
│   ├── images/
│   ├── stylesheets/
│   └── user-guide/
├── logging/
└── resources/
```

## :material-format-paint: Formatting

```powershell
black .\app.py .\boogr.py .\config.py
```

Review the formatter output before committing changes because the project may intentionally preserve an established local style.

## :material-language-python: Syntax Validation

```powershell
python -m py_compile .\app.py .\boogr.py .\config.py
```

## :material-book-check-outline: Documentation Validation

```powershell
mkdocs build --strict
```

Strict builds detect invalid navigation targets, unrecognized links, API collection failures, and Markdown issues.

## :material-monitor-eye: Local Preview

```powershell
mkdocs serve
```

The default local documentation address is typically `http://127.0.0.1:8000`.

## :material-check-decagram-outline: Change Audit

Before release:

- All required imports resolve.
- Session-state keys are initialized before use.
- Existing capture, filtering, analysis, and logging behavior remains available.
- Streamlit component keys remain unique and stable.
- Categorical count charts use automatic X-axis ticks.
- Plotly figures do not duplicate external Streamlit titles.
- Zero-, one-, and multi-category states render correctly.
- Background capture exceptions reach the capture-error queue.
- `mkdocs build --strict` completes without warnings.
