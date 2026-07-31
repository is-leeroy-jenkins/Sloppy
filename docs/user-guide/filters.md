# Filters

## :material-filter-outline: Global Filters

Global filters constrain the packet snapshot before mode-specific analysis.

Common filter dimensions:

- Protocol.
- Destination-port range.
- Source or destination address.
- Packet window.
- Capture session.

## :material-layers-outline: Mode-Specific Filters

| Mode          | Filter examples                                                                |
|---------------|--------------------------------------------------------------------------------|
| Data Link     | EtherType and frame class                                                      |
| Network Layer | IP version and address scope                                                   |
| Transport     | Protocol, source ports, destination ports, TCP flags, and transport indicators |
| Session       | Protocol, directionality, and activity state                                   |
| Presentation  | TLS version, handshake type, and ALPN                                          |
| Application   | Application protocol, DNS query type, HTTP method, and HTTP status             |

## :material-database-eye-outline: Snapshot Semantics

Filters operate on derived DataFrame snapshots. The original packet list in session state remains unchanged unless an explicit application control clears or replaces it.

## :material-table-filter: Empty and Sparse Results

- Empty snapshot: mode-specific informational state.
- One categorical value: summary table.
- Multiple categorical values: chart.
- Insufficient numeric variation: summary table instead of histogram.
