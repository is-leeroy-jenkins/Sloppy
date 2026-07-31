# Troubleshooting

## :material-chart-bar-stacked: Dense X-Axis Gridlines

**Cause:** A count axis configured with `dtick=1` generates a tick and gridline for every integer.

**Required configuration:**

```python
figure.update_xaxes(
    type='linear',
    rangemode='tozero',
    automargin=True,
    tickformat=',d',
)
```

Do not set `dtick` for ranked count charts unless the interval is deliberately bounded.

## :material-help-box-outline: `undefined` Inside a Plot

**Cause:** An invalid or incomplete Plotly title or trace name reaches the serialized figure.

**Controls:**

- Omit the Plotly title when Streamlit supplies the section heading.
- Set `showlegend=False` for single-series bars.
- Use an empty trace name and `<extra></extra>` in hover templates.

## :material-restart: Stale Application Code

Stop and restart Streamlit after replacing source files:

```powershell
Get-Process streamlit -ErrorAction SilentlyContinue | Stop-Process
streamlit run .\app.py
```

A hard browser refresh does not replace an already-running Python process.

## :material-access-point-remove: Live Capture Fails

Check:

- Scapy installation.
- Npcap installation on Windows.
- Interface selection.
- Elevated capture privileges.
- Firewall and endpoint-security restrictions.

Use demo/replay mode to validate the analysis interface without live-capture dependencies.

## :material-database-alert-outline: Logging Database Errors

Check:

- `LOG_DIR` and `LOG_PATH` values.
- Write permission on the logging directory.
- SQLite file locks.
- Available disk space.
- Retention and sanitization configuration.

## :material-file-document-alert-outline: MkDocs API Collection Errors

Run MkDocs from the project root so `app.py`, `boogr.py`, and `config.py` are visible on the configured handler path.

```powershell
mkdocs build --strict
```
