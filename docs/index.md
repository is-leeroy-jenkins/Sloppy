# Sloppy Network Analyzer

Sloppy is a Streamlit network-analysis application for packet capture, packet replay, protocol normalization, traffic filtering, OSI-layer analysis, interactive visualization, and SQLite-backed exception logging.

![Sloppy Network Analyzer](images/sloppy_project.png)

## :material-target: Core Capabilities

| Capability           | Implementation                                                                                    |
|----------------------|---------------------------------------------------------------------------------------------------|
| Packet acquisition   | Demo/replay generation and live Scapy capture                                                     |
| Normalization        | Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, TLS, HTTP, DNS, DHCP, and NTP metadata           |
| Analysis             | Network, Data Link, Network Layer, Transport, Session, Presentation, and Application modes        |
| Filtering            | Protocol, port, address, frame, TLS, DNS, application, and time-window filters                    |
| Visualization        | Plotly charts, metrics, matrices, timelines, relationship views, and read-only data editors       |
| Sparse-data handling | Informational state for zero categories, table for one category, chart for two or more categories |
| Logging              | Structured exception records written through `boogr.py` to `logging/Exceptions.db`                |

## :material-layers-triple: Analysis Coverage

| Mode                   | Primary scope                                                                                         |
|------------------------|-------------------------------------------------------------------------------------------------------|
| Network Analysis       | Overall packet activity, protocol mix, throughput, endpoints, ports, flows, and traffic relationships |
| Data Link Analysis     | Ethernet frames, MAC addresses, EtherType, ARP, VLAN, frame class, and MAC-to-IP relationships        |
| Network Layer Analysis | IPv4/IPv6, address scope, TTL/hop limit, fragmentation, DSCP/ECN, ICMP, and subnet relationships      |
| Transport Analysis     | TCP/UDP/ICMP behavior, ports, flags, windows, retransmission indicators, and transport distributions  |
| Session Analysis       | Bidirectional conversations, directional volume, duration, lifecycle, and activity state              |
| Presentation Analysis  | TLS versions, handshake metadata, SNI, ALPN, cipher suites, and certificate metadata when available   |
| Application Analysis   | DNS, HTTP, DHCP, and NTP metadata and activity                                                        |

## :material-magnify: Documentation Search

Search is enabled through the MkDocs `search` plugin and Material search features:

- Search suggestions while typing.
- Highlighted matches in pages.
- Shareable search-result URLs.
- Tokenization across whitespace, hyphens, and periods.

Use the search field in the site header or press <kbd>/</kbd> to focus search.

## :material-book-open-page-variant: Documentation Map

- [Architecture](architecture.md)
- [OSI Coverage](osi-layers.md)
- [Workflows](workflows.md)
- [User Guide](user-guide/index.md)
- [Logging](logging.md)
- [Configuration](configuration.md)
- [API Reference](api/index.md)
- [Development](development.md)
