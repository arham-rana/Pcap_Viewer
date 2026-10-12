# TraceLine — SIP/RTP Capture Analyzer

## What it extracts

- **SIP call-flow ladder diagrams** — every dialog grouped by Call-ID, rendered as an
  interactive signaling diagram: request/response arrows, timestamps, post-dial delay,
  retransmissions (flagged in red), User-Agent, and the negotiated RTP media session
  shown as a band between the endpoints. Click any arrow to jump to that raw packet.
- **RTP stream quality** — every media stream (SSRC, payload type/codec via SDP
  `rtpmap`), plus real quality metrics: RFC 3550 interarrival jitter, packet loss %,
  out-of-order packet count, and a rough estimated MOS score.
- **IP conversations & top talkers** — every host pair with packet/byte counts and
  throughput, plus a ranked top-talkers list.
- **DNS** — every query and response, with resolved answers.
- **TCP streams** — every stream with SYN/FIN/RST counts and retransmission detection.
- **TLS handshakes** — ClientHello version and SNI (server hostname) only; traffic is
  never decrypted.
- **ARP** — who-has / is-at request-reply pairs.
- **ICMP** — echo requests/replies and other ICMP message types.
- **Full packet inspection** — a searchable/filterable packet list (like a lightweight
  Wireshark packet pane) with per-packet detail and a raw hex dump.

## Quick start (Docker Compose)

```bash
docker compose up --build
```

Then open **http://localhost:8080**.

## Quick start (plain Docker)

```bash
docker build -t traceline .
docker run -p 8080:5000 -v traceline-uploads:/app/uploads traceline
```

## Usage

1. Click **Upload capture file** and choose a `.pcap`/`.pcapng`/`.cap` file.
2. Once parsed, use the tabs:
   - **Overview** — packet count, duration, protocol breakdown, top talkers.
   - **SIP Call Flow** — pick a call from the dropdown to see its ladder diagram.
   - **RTP Streams** — table of every detected media stream with quality metrics.
   - **Conversations** — top talkers and full IP conversation list.
   - **DNS** — every query/response pair with resolved answers.
   - **TCP Streams** — every TCP stream with handshake flags and retransmissions.
   - **Other Protocols** — TLS handshake metadata (SNI), ARP, and ICMP.
   - **Packet List** — filter by IP/frame/info text or protocol; click a row to see
     the decoded summary and hex dump for that frame.

## How detection works

- **SIP** is detected by inspecting UDP/TCP payloads for a SIP request line or
  `SIP/2.0` status line (not tied to port 5060), and headers/SDP bodies are parsed
  for Call-ID, From/To, CSeq, and negotiated media (`c=`, `m=audio`, `a=rtpmap`).
- **RTP** is detected heuristically on UDP payloads that match the RTP header
  format (version 2), grouped into streams by 5-tuple + SSRC, and matched back to
  SIP calls using the negotiated SDP media IP/port when available.

## Notes

- Analyses are kept in memory for the life of the container (per upload) — restarting
  the container clears them. This is intended as a diagnostic tool, not long-term storage.
- Max upload size defaults to 200 MB; override with the `MAX_UPLOAD_MB` environment
  variable.
- Large captures (100k+ packets) will parse but the packet list currently returns up
  to 2000 rows per query — use the search/protocol filters to narrow results.
