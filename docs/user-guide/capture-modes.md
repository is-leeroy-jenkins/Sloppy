# Capture Modes

## :material-movie-open-play-outline: Demo / Replay

Demo/replay mode produces representative packet records for the supported analysis modes.

Characteristics:

- No network interface selection.
- No elevated capture privileges.
- Deterministic protocol coverage for interface validation and demonstrations.
- Records enter the same queue, normalization, storage, filtering, and rendering paths used by live capture.

## :material-access-point-network: Live Capture

Live capture uses Scapy on a background thread.

Operational sequence:

1. Validate the selected interface and capture state.
2. Initialize the stop event.
3. Start the capture thread.
4. Normalize supported packet metadata in the callback.
5. Place records in the packet queue.
6. Drain the queue during Streamlit reruns.
7. Display background errors from the capture-error queue.

## :material-stop-circle-outline: Stop Behavior

Stopping capture signals the background thread and prevents additional packet ingestion. Existing session-state records remain available until explicitly replaced or cleared by application controls.

## :material-alert-circle-outline: Capture Limitations

- Encrypted payload contents remain unavailable unless exposed through handshake metadata.
- Unsupported protocols retain common packet metadata but may lack specialized fields.
- Capture visibility depends on host interface placement and network architecture.
- Physical-layer signal and link telemetry are outside the application scope.
