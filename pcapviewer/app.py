import os
import re
import math
import uuid
import struct
import threading
from datetime import datetime, timezone

from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
from scapy.all import (
    rdpcap, Ether, IP, IPv6, TCP, UDP, Raw, ARP, ICMP, DNS, DNSQR, DNSRR
)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(APP_ROOT, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "200"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

ANALYSES = {}
LOCK = threading.Lock()

SIP_METHODS = (
    "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", "PRACK",
    "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER", "MESSAGE", "UPDATE"
)

STATIC_PT_CODECS = {
    0: ("PCMU", 8000), 3: ("GSM", 8000), 4: ("G723", 8000), 5: ("DVI4", 8000),
    6: ("DVI4", 16000), 7: ("LPC", 8000), 8: ("PCMA", 8000), 9: ("G722", 8000),
    10: ("L16", 44100), 11: ("L16", 44100), 12: ("QCELP", 8000), 13: ("CN", 8000),
    15: ("G728", 8000), 18: ("G729", 8000), 25: ("CelB", 90000), 26: ("JPEG", 90000),
    31: ("H261", 90000), 32: ("MPV", 90000), 33: ("MP2T", 90000), 34: ("H263", 90000),
}

ICMP_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
    5: "Redirect", 8: "Echo Request", 9: "Router Advertisement",
    10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem",
    13: "Timestamp Request", 14: "Timestamp Reply",
}

TLS_HANDSHAKE_TYPES = {1: "ClientHello", 2: "ServerHello", 11: "Certificate", 14: "ServerHelloDone"}
TLS_VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


def ts_iso(t):
    return datetime.fromtimestamp(float(t), tz=timezone.utc).isoformat()


def conv_key(a, b):
    return tuple(sorted([a, b]))


# ----------------------------- SIP -----------------------------

def classify_sip(payload_text):
    if not payload_text:
        return None
    first_line = payload_text.split("\r\n", 1)[0].split("\n", 1)[0].strip()
    is_response = first_line.startswith("SIP/2.0")
    is_request = False
    method = None
    if not is_response:
        parts = first_line.split(" ")
        if len(parts) >= 3 and parts[0] in SIP_METHODS and parts[-1].startswith("SIP/2.0"):
            is_request = True
            method = parts[0]
    if not (is_response or is_request):
        return None

    headers = {}
    lines = re.split(r"\r\n|\n", payload_text)
    body_start = None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "":
            body_start = i + 1
            break
        m = re.match(r"^([A-Za-z\-]+):\s*(.*)$", line)
        if m:
            headers.setdefault(m.group(1).lower(), m.group(2).strip())
    body = "\r\n".join(lines[body_start:]) if body_start else ""

    def h(*names):
        for n in names:
            if n in headers:
                return headers[n]
        return None

    call_id = h("call-id", "i")
    cseq_raw = h("cseq")
    cseq_num, cseq_method = None, None
    if cseq_raw:
        m = re.match(r"(\d+)\s+(\w+)", cseq_raw)
        if m:
            cseq_num, cseq_method = m.group(1), m.group(2)

    status_code, reason = None, None
    if is_response:
        m = re.match(r"SIP/2\.0\s+(\d+)\s*(.*)", first_line)
        if m:
            status_code, reason = m.group(1), m.group(2)

    sdp = None
    if "sdp" in (h("content-type", "c") or "").lower() and body.strip():
        sdp = parse_sdp(body)

    return {
        "is_request": is_request, "is_response": is_response,
        "method": method, "status_code": status_code, "reason": reason,
        "call_id": call_id, "from_hdr": h("from", "f"), "to_hdr": h("to", "t"),
        "via": h("via", "v"), "cseq": cseq_num, "cseq_method": cseq_method,
        "contact": h("contact", "m"), "user_agent": h("user-agent", "server"),
        "p_asserted_identity": h("p-asserted-identity"),
        "summary": first_line, "sdp": sdp,
    }


def parse_sdp(body):
    media_ip = None
    m = re.search(r"^c=IN IP[46]\s+(\S+)", body, re.MULTILINE)
    if m:
        media_ip = m.group(1)
    media = []
    for mm in re.finditer(r"^m=(\w+)\s+(\d+)\s+\S+\s+(.*)$", body, re.MULTILINE):
        media.append({"type": mm.group(1), "port": int(mm.group(2)), "fmts": mm.group(3).split()})
    rtpmap = {}
    for rm in re.finditer(r"^a=rtpmap:(\d+)\s+(\S+)", body, re.MULTILINE):
        rtpmap[int(rm.group(1))] = rm.group(2)
    return {"ip": media_ip, "media": media, "rtpmap": rtpmap}


# ----------------------------- RTP -----------------------------

def try_parse_rtp(payload):
    if len(payload) < 12:
        return None
    b0, b1 = payload[0], payload[1]
    version = b0 >> 6
    if version != 2:
        return None
    marker = (b1 >> 7) & 1
    pt = b1 & 0x7F
    try:
        seq, timestamp, ssrc = struct.unpack("!HII", payload[2:12])
    except struct.error:
        return None
    return {"marker": marker, "pt": pt, "seq": seq, "timestamp": timestamp, "ssrc": ssrc}


def compute_rtp_quality(pkt_list, clock_rate):
    """pkt_list: list of (arrival_time, rtp_timestamp, seq) in packet-arrival order."""
    if len(pkt_list) < 2:
        return {"jitter_ms": 0.0, "out_of_order": 0, "loss_pct": 0.0, "mos": None}

    # extended (unwrapped) sequence numbers to handle 16-bit wraparound
    ext_seqs = []
    base = pkt_list[0][2]
    prev_seq = base
    wraps = 0
    for _, _, seq in pkt_list:
        if seq < prev_seq - 32768:
            wraps += 1
        elif seq > prev_seq + 32768:
            wraps -= 1
        ext_seqs.append(seq + wraps * 65536)
        prev_seq = seq

    out_of_order = sum(1 for i in range(1, len(ext_seqs)) if ext_seqs[i] < ext_seqs[i - 1])

    seq_min, seq_max = min(ext_seqs), max(ext_seqs)
    expected = seq_max - seq_min + 1
    received = len(set(ext_seqs))
    lost = max(expected - received, 0)
    loss_pct = round((lost / expected) * 100, 2) if expected > 0 else 0.0

    # RFC 3550 interarrival jitter (in RTP timestamp units, then converted to ms)
    jitter = 0.0
    prev_arrival, prev_rtp_ts = pkt_list[0][0], pkt_list[0][1]
    for arrival, rtp_ts, _ in pkt_list[1:]:
        d_arrival = arrival - prev_arrival
        d_rtp = (rtp_ts - prev_rtp_ts) / clock_rate
        d = abs(d_arrival - d_rtp)
        jitter += (d - jitter) / 16.0
        prev_arrival, prev_rtp_ts = arrival, rtp_ts
    jitter_ms = round(jitter * 1000, 2)

    mos = estimate_mos(loss_pct, jitter_ms)

    return {"jitter_ms": jitter_ms, "out_of_order": out_of_order, "loss_pct": loss_pct, "mos": mos}


def estimate_mos(loss_pct, jitter_ms):
    """Rough E-model-based MOS estimate for a G.711-class codec. Approximate only —
    real MOS depends on codec, burst pattern, and end-to-end delay this tool can't see."""
    effective_delay_penalty = min(jitter_ms * 2, 40)  # crude jitter buffer proxy
    ie = 30 * math.log(1 + 15 * (loss_pct / 100.0) * 10) if loss_pct > 0 else 0
    r = 93.2 - ie - (effective_delay_penalty / 10.0)
    r = max(0, min(r, 100))
    mos = 1 + 0.035 * r + r * (r - 60) * (100 - r) * 7e-6
    return round(max(1.0, min(mos, 4.5)), 2)


# ----------------------------- TLS (metadata only, no decryption) -----------------------------

def try_parse_tls_client_hello(payload):
    """Detect a TLS record containing a ClientHello and pull SNI + version. Best-effort,
    handles the common single-record case."""
    if len(payload) < 6 or payload[0] != 0x16:
        return None
    record_ver = struct.unpack("!H", payload[1:3])[0]
    if record_ver not in (0x0301, 0x0302, 0x0303, 0x0300):
        return None
    try:
        hs_type = payload[5]
        if hs_type != 1:
            return None
        pos = 9  # skip record header(5) + handshake header(4)
        client_ver = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + 32  # version + random
        sess_len = payload[pos]
        pos += 1 + sess_len
        cs_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + cs_len
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return {"version": TLS_VERSIONS.get(client_ver, hex(client_ver)), "sni": None}
        ext_total_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        end = min(pos + ext_total_len, len(payload))
        sni = None
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
            ext_body = payload[pos + 4: pos + 4 + ext_len]
            if ext_type == 0 and len(ext_body) > 2:  # server_name
                list_len = struct.unpack("!H", ext_body[0:2])[0]
                sp = 2
                sub = ext_body[2:2 + list_len]
                if len(sub) >= 3:
                    name_len = struct.unpack("!H", sub[1:3])[0]
                    sni = sub[3:3 + name_len].decode("utf-8", errors="ignore")
            pos += 4 + ext_len
        return {"version": TLS_VERSIONS.get(client_ver, hex(client_ver)), "sni": sni}
    except (struct.error, IndexError):
        return None


# ----------------------------- Main parse -----------------------------

def parse_pcap(path, original_name):
    packets = rdpcap(path)
    frames = []
    raw_store = {}
    sip_by_call = {}
    rtp_candidates = {}
    dns_records = []
    arp_records = []
    icmp_records = []
    tls_records = []
    tcp_streams = {}
    ip_conversations = {}
    endpoint_stats = {}
    proto_counts = {}
    start_time, end_time = None, None

    for idx, pkt in enumerate(packets, start=1):
        t = float(pkt.time)
        if start_time is None or t < start_time:
            start_time = t
        if end_time is None or t > end_time:
            end_time = t

        src = dst = "-"
        sport = dport = None
        length = len(bytes(pkt))
        l4 = None
        proto = "OTHER"

        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst

        if src != "-" and dst != "-":
            ck = conv_key(src, dst)
            c = ip_conversations.setdefault(ck, {
                "a": ck[0], "b": ck[1], "packets": 0, "bytes": 0,
                "first_time": t, "last_time": t, "protocols": set(),
            })
            c["packets"] += 1
            c["bytes"] += length
            c["last_time"] = t
            for ip_addr, other, direction in ((src, dst, "sent"), (dst, src, "recv")):
                es = endpoint_stats.setdefault(ip_addr, {
                    "ip": ip_addr, "packets": 0, "bytes": 0, "peers": set(),
                })
                es["packets"] += 1
                es["bytes"] += length
                es["peers"].add(other)

        payload_bytes = b""
        if UDP in pkt:
            l4 = "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            if Raw in pkt:
                payload_bytes = bytes(pkt[Raw].load)
        elif TCP in pkt:
            l4 = "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            if Raw in pkt:
                payload_bytes = bytes(pkt[Raw].load)
        elif IP in pkt or IPv6 in pkt:
            l4 = "IP"

        info = ""
        sip_msg = None

        # --- ARP ---
        if ARP in pkt:
            proto = "ARP"
            a = pkt[ARP]
            op = "who-has" if a.op == 1 else ("is-at" if a.op == 2 else str(a.op))
            info = f"{op} {a.pdst}" + (f" tell {a.psrc}" if a.op == 1 else f" is {a.hwsrc}")
            arp_records.append({
                "frame": idx, "time": t, "op": op,
                "sender_ip": a.psrc, "sender_mac": a.hwsrc,
                "target_ip": a.pdst, "target_mac": a.hwdst,
            })

        # --- ICMP ---
        elif ICMP in pkt:
            proto = "ICMP"
            ic = pkt[ICMP]
            type_name = ICMP_TYPES.get(ic.type, f"type {ic.type}")
            info = f"{type_name} (code {ic.code})"
            icmp_records.append({
                "frame": idx, "time": t, "src": src, "dst": dst,
                "type": ic.type, "code": ic.code, "description": type_name,
            })

        # --- DNS ---
        elif DNS in pkt and (l4 == "UDP" or l4 == "TCP"):
            proto = "DNS"
            d = pkt[DNS]
            is_response = d.qr == 1
            qname = None
            qtype = None
            if d.qdcount and d.qd is not None:
                try:
                    qname = d.qd.qname.decode(errors="ignore").rstrip(".")
                    qtype = d.qd.qtype
                except Exception:
                    pass
            answers = []
            if is_response and d.ancount:
                an = d.an
                for _ in range(d.ancount):
                    if an is None:
                        break
                    try:
                        rdata = an.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode(errors="ignore")
                        answers.append(str(rdata))
                    except Exception:
                        pass
                    an = an.payload if hasattr(an, "payload") and isinstance(an.payload, type(an)) else None
            info = (f'{"Response" if is_response else "Query"} {qname or ""}'
                    + (f' -> {", ".join(answers)}' if answers else ""))
            dns_records.append({
                "frame": idx, "time": t, "src": src, "dst": dst,
                "is_response": is_response, "query_name": qname,
                "query_type": qtype, "answers": answers,
            })

        # --- SIP / RTP / TLS / generic UDP-TCP ---
        elif payload_bytes and l4 in ("UDP", "TCP"):
            text = None
            try:
                text = payload_bytes.decode("utf-8", errors="ignore")
            except Exception:
                text = None
            sip_msg = classify_sip(text) if text else None

            if sip_msg:
                proto = "SIP"
                if sip_msg["is_request"]:
                    info = f'{sip_msg["method"]} (Call-ID: {sip_msg["call_id"]})'
                else:
                    info = f'SIP/2.0 {sip_msg["status_code"]} {sip_msg["reason"]} (Call-ID: {sip_msg["call_id"]})'
                entry = dict(sip_msg)
                entry.update({"frame": idx, "time": t, "src": src, "dst": dst,
                               "sport": sport, "dport": dport})
                cid = sip_msg["call_id"] or "unknown"
                sip_by_call.setdefault(cid, []).append(entry)

            elif l4 == "UDP":
                rtp_info = try_parse_rtp(payload_bytes)
                if rtp_info:
                    proto = "RTP"
                    info = (f'PT={rtp_info["pt"]} SSRC=0x{rtp_info["ssrc"]:08X} '
                            f'Seq={rtp_info["seq"]} Time={rtp_info["timestamp"]}')
                    key = (src, sport, dst, dport, rtp_info["ssrc"])
                    s = rtp_candidates.setdefault(key, {
                        "src": src, "sport": sport, "dst": dst, "dport": dport,
                        "ssrc": rtp_info["ssrc"], "pt": rtp_info["pt"],
                        "count": 0, "first_time": t, "last_time": t,
                        "bytes": 0, "samples": [],
                    })
                    s["count"] += 1
                    s["last_time"] = t
                    s["bytes"] += len(payload_bytes)
                    if len(s["samples"]) < 20000:
                        s["samples"].append((t, rtp_info["timestamp"], rtp_info["seq"]))
                else:
                    proto = "UDP"
                    info = f"{sport} -> {dport} Len={len(payload_bytes)}"

            elif l4 == "TCP":
                tls = try_parse_tls_client_hello(payload_bytes)
                if tls:
                    proto = "TLS"
                    info = f'ClientHello {tls["version"]}' + (f' SNI={tls["sni"]}' if tls["sni"] else "")
                    tls_records.append({
                        "frame": idx, "time": t, "src": src, "dst": dst,
                        "sport": sport, "dport": dport,
                        "sni": tls["sni"], "version": tls["version"],
                    })
                else:
                    proto = "TCP"
                    flags = str(pkt[TCP].flags) if TCP in pkt else ""
                    info = f"{sport} -> {dport} [{flags}] Len={len(payload_bytes)}"

        elif l4 == "TCP":
            proto = "TCP"
            flags = str(pkt[TCP].flags) if TCP in pkt else ""
            info = f"{sport} -> {dport} [{flags}]"
        elif IP in pkt or IPv6 in pkt:
            info = f"proto={pkt[IP].proto if IP in pkt else 'ipv6'}"
        else:
            proto = "L2"
            info = pkt.summary()

        # --- TCP stream tracking (independent of payload classification above) ---
        if TCP in pkt:
            skey = conv_key(f"{src}:{sport}", f"{dst}:{dport}")
            st = tcp_streams.setdefault(skey, {
                "a": skey[0], "b": skey[1], "packets": 0, "bytes": 0,
                "syn": 0, "fin": 0, "rst": 0, "first_time": t, "last_time": t,
                "seen_seqs": {}, "retransmissions": 0,
            })
            st["packets"] += 1
            st["bytes"] += length
            st["last_time"] = t
            fl = pkt[TCP].flags
            if fl & 0x02:
                st["syn"] += 1
            if fl & 0x01:
                st["fin"] += 1
            if fl & 0x04:
                st["rst"] += 1
            if payload_bytes:
                dir_key = (src, sport)
                seq = pkt[TCP].seq
                seen = st["seen_seqs"].setdefault(dir_key, set())
                if seq in seen:
                    st["retransmissions"] += 1
                else:
                    seen.add(seq)

        proto_counts[proto] = proto_counts.get(proto, 0) + 1
        raw_store[idx] = bytes(pkt)
        frames.append({
            "frame": idx, "time": t, "time_rel": None,
            "src": src, "dst": dst, "sport": sport, "dport": dport,
            "proto": proto, "length": length, "info": info,
        })

    if start_time is not None:
        for f in frames:
            f["time_rel"] = round(f["time"] - start_time, 6)

    # ---- finalize RTP streams with quality metrics ----
    rtp_streams = []
    for i, (key, s) in enumerate(rtp_candidates.items(), start=1):
        if s["count"] < 3:
            continue
        duration = max(s["last_time"] - s["first_time"], 0.0001)
        codec_name, clock_rate = STATIC_PT_CODECS.get(s["pt"], (f'dynamic({s["pt"]})', 8000))
        quality = compute_rtp_quality(s["samples"], clock_rate)
        rtp_streams.append({
            "id": i, "src": s["src"], "sport": s["sport"],
            "dst": s["dst"], "dport": s["dport"],
            "ssrc": f'0x{s["ssrc"]:08X}', "payload_type": s["pt"],
            "codec": f"{codec_name}/{clock_rate}" if isinstance(codec_name, str) and "/" not in codec_name else codec_name,
            "packet_count": s["count"],
            "duration_sec": round(duration, 3),
            "avg_pps": round(s["count"] / duration, 1),
            "bytes": s["bytes"],
            "jitter_ms": quality["jitter_ms"],
            "loss_pct": quality["loss_pct"],
            "out_of_order": quality["out_of_order"],
            "mos_estimate": quality["mos"],
            "start_time": s["first_time"], "end_time": s["last_time"],
        })

    rtpmap_by_port = {}
    for cid, msgs in sip_by_call.items():
        for m in msgs:
            sdp = m.get("sdp")
            if sdp and sdp.get("rtpmap"):
                for med in sdp.get("media", []):
                    rtpmap_by_port[med["port"]] = sdp["rtpmap"]
    for rs in rtp_streams:
        rmap = rtpmap_by_port.get(rs["dport"]) or rtpmap_by_port.get(rs["sport"])
        if rmap and rs["payload_type"] in rmap:
            rs["codec"] = rmap[rs["payload_type"]]

    # ---- SIP call summaries (with retransmission flags) ----
    calls = {}
    for cid, msgs in sip_by_call.items():
        msgs.sort(key=lambda m: m["time"])
        seen_txn = set()
        for m in msgs:
            txn_key = (m.get("cseq"), m.get("cseq_method"), m["src"], m["is_request"], m.get("status_code"))
            m["is_retransmission"] = txn_key in seen_txn
            seen_txn.add(txn_key)

        participants = []
        for m in msgs:
            for ep in (f'{m["src"]}:{m["sport"]}', f'{m["dst"]}:{m["dport"]}'):
                if ep not in participants:
                    participants.append(ep)

        first, last = msgs[0], msgs[-1]
        final_status = None
        first_provisional_time = None
        for m in msgs:
            if m["is_response"] and m.get("cseq_method") == "INVITE":
                code = int(m["status_code"]) if m["status_code"] else 0
                if 100 <= code < 200 and first_provisional_time is None:
                    first_provisional_time = m["time"]
                if code >= 200:
                    final_status = f'{m["status_code"]} {m["reason"]}'

        media_endpoints = []
        for m in msgs:
            sdp = m.get("sdp")
            if sdp and sdp.get("ip"):
                for med in sdp.get("media", []):
                    ep = f'{sdp["ip"]}:{med["port"]}'
                    if ep not in media_endpoints:
                        media_endpoints.append(ep)

        retrans_count = sum(1 for m in msgs if m["is_retransmission"])

        calls[cid] = {
            "call_id": cid,
            "participants": participants,
            "message_count": len(msgs),
            "start_time": first["time"],
            "end_time": last["time"],
            "duration_sec": round(last["time"] - first["time"], 3),
            "post_dial_delay_sec": (round(first_provisional_time - first["time"], 3)
                                     if first_provisional_time else None),
            "final_status": final_status,
            "media_endpoints": media_endpoints,
            "retransmission_count": retrans_count,
            "from_hdr": first.get("from_hdr"),
            "to_hdr": first.get("to_hdr"),
            "user_agent": next((m.get("user_agent") for m in msgs if m.get("user_agent")), None),
            "messages": [
                {
                    "frame": m["frame"], "time": m["time"],
                    "time_rel": round(m["time"] - start_time, 6) if start_time else 0,
                    "src": f'{m["src"]}:{m["sport"]}', "dst": f'{m["dst"]}:{m["dport"]}',
                    "is_request": m["is_request"],
                    "label": (m["method"] if m["is_request"]
                              else f'{m["status_code"]} {m["reason"]}'),
                    "cseq": m["cseq"], "cseq_method": m["cseq_method"],
                    "has_sdp": bool(m.get("sdp")),
                    "is_retransmission": m["is_retransmission"],
                }
                for m in msgs
            ],
        }

    # ---- conversations / top talkers ----
    ip_conv_list = []
    for (a, b), c in ip_conversations.items():
        dur = max(c["last_time"] - c["first_time"], 0.0001)
        ip_conv_list.append({
            "a": a, "b": b, "packets": c["packets"], "bytes": c["bytes"],
            "duration_sec": round(dur, 3),
            "avg_bps": round((c["bytes"] * 8) / dur, 1),
        })
    ip_conv_list.sort(key=lambda x: -x["bytes"])

    top_talkers = sorted(
        ({"ip": ip, "packets": v["packets"], "bytes": v["bytes"], "peer_count": len(v["peers"])}
         for ip, v in endpoint_stats.items()),
        key=lambda x: -x["bytes"]
    )[:25]

    # ---- tcp streams finalize ----
    tcp_stream_list = []
    for (a, b), st in tcp_streams.items():
        dur = max(st["last_time"] - st["first_time"], 0.0001)
        tcp_stream_list.append({
            "a": a, "b": b, "packets": st["packets"], "bytes": st["bytes"],
            "syn": st["syn"], "fin": st["fin"], "rst": st["rst"],
            "retransmissions": st["retransmissions"],
            "duration_sec": round(dur, 3),
        })
    tcp_stream_list.sort(key=lambda x: -x["bytes"])

    summary = {
        "file_name": original_name,
        "packet_count": len(frames),
        "start_time": ts_iso(start_time) if start_time else None,
        "end_time": ts_iso(end_time) if end_time else None,
        "duration_sec": round((end_time - start_time), 3) if start_time and end_time else 0,
        "proto_counts": proto_counts,
        "sip_call_count": len(calls),
        "rtp_stream_count": len(rtp_streams),
        "dns_query_count": len(dns_records),
        "tcp_stream_count": len(tcp_stream_list),
        "arp_count": len(arp_records),
        "icmp_count": len(icmp_records),
        "tls_handshake_count": len(tls_records),
        "unique_hosts": len(endpoint_stats),
        "top_talkers": top_talkers[:5],
    }

    return {
        "summary": summary,
        "frames": frames,
        "raw": raw_store,
        "calls": calls,
        "rtp_streams": rtp_streams,
        "dns_records": dns_records,
        "arp_records": arp_records,
        "icmp_records": icmp_records,
        "tls_records": tls_records,
        "tcp_streams": tcp_stream_list,
        "ip_conversations": ip_conv_list,
        "top_talkers": top_talkers,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = secure_filename(f.filename)
    if not filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        return jsonify({"error": "Please upload a .pcap, .pcapng, or .cap file"}), 400

    aid = uuid.uuid4().hex[:12]
    save_path = os.path.join(UPLOAD_DIR, f"{aid}_{filename}")
    f.save(save_path)

    try:
        analysis = parse_pcap(save_path, filename)
    except Exception as e:
        return jsonify({"error": f"Failed to parse capture: {e}"}), 400

    with LOCK:
        ANALYSES[aid] = analysis

    return jsonify({"analysis_id": aid, "summary": analysis["summary"]})


def get_analysis_or_404(aid):
    with LOCK:
        return ANALYSES.get(aid)


@app.route("/api/analysis/<aid>/summary")
def api_summary(aid):
    a = get_analysis_or_404(aid)
    if not a:
        return jsonify({"error": "not found"}), 404
    return jsonify(a["summary"])


@app.route("/api/analysis/<aid>/packets")
def api_packets(aid):
    a = get_analysis_or_404(aid)
    if not a:
        return jsonify({"error": "not found"}), 404
    q = request.args.get("q", "").strip().lower()
    proto = request.args.get("proto", "").strip().upper()
    offset = int(request.args.get("offset", 0))
    limit = min(int(request.args.get("limit", 500)), 2000)

    frames = a["frames"]
    if proto:
        frames = [f for f in frames if f["proto"] == proto]
    if q:
        frames = [f for f in frames if q in str(f["src"]).lower()
                  or q in str(f["dst"]).lower() or q in str(f["info"]).lower()
                  or q in str(f["frame"])]

    return jsonify({"total": len(frames), "packets": frames[offset:offset + limit]})


@app.route("/api/analysis/<aid>/packet/<int:frame_no>")
def api_packet_detail(aid, frame_no):
    a = get_analysis_or_404(aid)
    if not a:
        return jsonify({"error": "not found"}), 404
    raw = a["raw"].get(frame_no)
    if raw is None:
        return jsonify({"error": "frame not found"}), 404
    frame = next((f for f in a["frames"] if f["frame"] == frame_no), None)
    return jsonify({"frame": frame, "hexdump": to_hexdump(raw), "length": len(raw)})


def to_hexdump(data):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


@app.route("/api/analysis/<aid>/sip")
def api_sip(aid):
    a = get_analysis_or_404(aid)
    if not a:
        return jsonify({"error": "not found"}), 404
    calls = sorted(a["calls"].values(), key=lambda c: c["start_time"])
    return jsonify({"calls": calls})


@app.route("/api/analysis/<aid>/rtp")
def api_rtp(aid):
    a = get_analysis_or_404(aid)
    if not a:
        return jsonify({"error": "not found"}), 404
    return jsonify({"streams": a["rtp_streams"]})


@app.route("/api/analysis/<aid>/dns")
def api_dns(aid):
    a = get_analysis_or_404(aid)
    if not a:
        return jsonify({"error": "not found"}), 404
    return jsonify({"records": a["dns_records"]})


@app.route("/api/analysis/<aid>/tcp")
def api_tcp(aid):
    a = get_analysis_or_404(aid)
    if not a:
        return jsonify({"error": "not found"}), 404
    return jsonify({"streams": a["tcp_streams"]})


@app.route("/api/analysis/<aid>/other")
def api_other(aid):
    a = get_analysis_or_404(aid)
    if not a:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "arp": a["arp_records"],
        "icmp": a["icmp_records"],
        "tls": a["tls_records"],
    })


@app.route("/api/analysis/<aid>/conversations")
def api_conversations(aid):
    a = get_analysis_or_404(aid)
    if not a:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "ip_conversations": a["ip_conversations"],
        "top_talkers": a["top_talkers"],
    })


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
