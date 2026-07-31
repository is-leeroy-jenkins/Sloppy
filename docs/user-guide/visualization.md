# Visualization Behavior

## :material-chart-bar: Categorical Charts

Horizontal ranking charts use:

- Count values on the linear X axis.
- Category labels on the categorical Y axis.
- Automatic tick spacing.
- Integer tick formatting.
- Deterministic category ordering.
- Hidden legends for single-series traces.

Fixed `dtick=1` is not used because large counts would produce dense gridlines and unreadable tick labels.

## :material-format-title: Titles

Streamlit section headings provide the visible visualization title. Plotly figures omit redundant internal titles. This avoids duplicated headings and prevents invalid empty title values from rendering as `undefined`.

## :material-table-large: Single-Category Results

A read-only `st.data_editor` replaces a chart when only one category is available. The table retains the same external section heading used by the chart state.

## :material-chart-bell-curve-cumulative: Numeric Results

Histograms require sufficient observations and variation. A read-only summary table is used when fewer than two usable values exist or all values are identical.

## :material-arrow-expand-vertical: Layout Stability

Tables and charts use bounded heights and stable component keys to reduce layout movement during Streamlit reruns.
