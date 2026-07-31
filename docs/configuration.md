# Configuration

## :material-cog-outline: Sources

`config.py` combines fixed application constants with environment-backed values.

Environment helper functions:

| Function    | Purpose                                    |
|-------------|--------------------------------------------|
| `get_bool`  | Parse Boolean environment variables        |
| `get_int`   | Parse integer environment variables        |
| `get_float` | Parse floating-point environment variables |
| `get_path`  | Resolve path environment variables         |
| `get_text`  | Read text environment variables            |

## :material-folder-outline: Paths

| Setting                 | Purpose                   |
|-------------------------|---------------------------|
| `BASE_DIR` / `ROOT_DIR` | Project-root resolution   |
| `ASSETS_DIR`            | Application assets        |
| `DOCS_DIR`              | Documentation files       |
| `LOG_DIR`               | Logging directory         |
| `LOG_PATH`              | SQLite exception database |
| `LOG_FILE`              | Logical logging file name |

## :material-palette-outline: Visual Theme

Configuration defines:

- Primary and secondary accent colors.
- Page and panel backgrounds.
- Grid, border, text, and muted-text colors.
- Protocol-specific colors.
- EtherType, ARP, and frame-class colors.

## :material-layers-triple-outline: Analysis Modes

Configured labels:

- `ANALYSIS_MODE_NETWORK`
- `ANALYSIS_MODE_DATA_LINK`
- `ANALYSIS_MODE_NETWORK_LAYER`
- `ANALYSIS_MODE_TRANSPORT`
- `ANALYSIS_MODE_SESSION`
- `ANALYSIS_MODE_PRESENTATION`
- `ANALYSIS_MODE_APPLICATION`

`ANALYSIS_MODES` defines their UI order.

## :material-chart-box-outline: Visualization Limits

Visualization constants control:

- Figure heights.
- Maximum categories.
- Sparse-data thresholds.
- Data-editor heights and row limits.
- Unknown-category labels.
- Packet-window and rendering limits.

## :material-shield-key-outline: Environment Overrides

Environment-backed values preserve deterministic defaults. Invalid values fall back to the configured default rather than interrupting module import.
