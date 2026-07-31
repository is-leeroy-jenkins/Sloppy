# Overview

## Purpose

The user interface combines capture controls, mode-specific filters, real-time metrics, analytical visualizations, and read-only packet or relationship tables.

## Main workflow

1. Select an analysis mode in the sidebar.
2. Choose demonstration traffic or live capture.
3. Configure the capture and mode filters.
4. Start or maintain capture.
5. Review metrics and visualizations.
6. Inspect normalized records in the mode editor.
7. Stop capture before changing interfaces or ending the session.

## Data model

A packet record may include:

- Capture metadata such as timestamp, session identifier, interface, and frame length.
- Data-link metadata such as source and destination MAC addresses, EtherType, VLAN, and ARP fields.
- Network metadata such as IP version, source and destination addresses, TTL or hop limit, DSCP, ECN, and ICMP fields.
- Transport metadata such as protocol, ports, flags, sequence numbers, acknowledgements, and window size.
- Presentation metadata such as TLS version, handshake type, cipher suite, SNI, ALPN, certificate count, and alert information.
- Application metadata such as DNS, HTTP, DHCP, and NTP fields.

Not every record contains every field. Missing values indicate that the layer or protocol was not present, was not selected, or could not be parsed from the observable packet bytes.
