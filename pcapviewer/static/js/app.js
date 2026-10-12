(() => {
  const state = {
    analysisId: null,
    summary: null,
    calls: [],
    rtpStreams: [],
    packetsCache: [],
    packetOffset: 0,
    packetTotal: 0,
  };

  const $ = (sel) => document.querySelector(sel);

  async function fetchJSON(url, opts) {
    const res = await fetch(url, opts);
    let data;
    try {
      data = await res.json();
    } catch {
      throw new Error(`Server returned an invalid response (status ${res.status})`);
    }
    if (!res.ok) {
      throw new Error(data.error || `Request failed (status ${res.status})`);
    }
    return data;
  }

  const el = (tag, attrs = {}, children = []) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = v;
      else e.setAttribute(k, v);
    }
    children.forEach((c) => e.appendChild(c));
    return e;
  };

  // ---------- Status line ----------
  function setStatus(msg, kind) {
    const s = $("#statusline");
    s.hidden = false;
    s.textContent = msg;
    s.className = "statusline" + (kind ? " " + kind : "");
  }

  // ---------- Upload ----------
  $("#fileInput").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    $("#fileName").textContent = file.name;
    setStatus(`Parsing ${file.name}…`, "busy");

    const form = new FormData();
    form.append("file", file);
    try {
      const data = await fetchJSON("/api/upload", { method: "POST", body: form });
      state.analysisId = data.analysis_id;
      state.summary = data.summary;
      setStatus(
        `Loaded ${data.summary.file_name} — ${data.summary.packet_count} packets, ` +
        `${data.summary.sip_call_count} SIP call(s), ${data.summary.rtp_stream_count} RTP stream(s)`,
        "ok"
      );
      $("#emptyState").hidden = true;
      $("#tabs").hidden = false;
      await loadAll();
      activateTab("overview");
    } catch (err) {
      setStatus("Network error while uploading: " + err.message, "error");
    }
  });

  // ---------- Tabs ----------
  document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => activateTab(btn.dataset.tab));
  });
  function activateTab(name) {
    document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
    document.querySelectorAll(".tab-panel").forEach((p) => (p.hidden = true));
    $(`#panel-${name}`).hidden = false;
  }

  async function loadAll() {
    await Promise.all([
      loadOverview(), loadSip(), loadRtp(), loadConversations(),
      loadDns(), loadTcp(), loadOther(), loadPacketsInitial(),
    ]);
  }

  // ---------- Overview ----------
  async function loadOverview() {
    const s = state.summary;
    const grid = $("#overviewGrid");
    grid.innerHTML = "";

    const cards = [
      ["Total packets", s.packet_count, ""],
      ["Capture duration", s.duration_sec + "s", ""],
      ["SIP calls", s.sip_call_count, ""],
      ["RTP streams", s.rtp_stream_count, ""],
    ];
    cards.forEach(([label, value]) => {
      grid.appendChild(
        el("div", { class: "stat-card" }, [
          el("div", { class: "label", text: label }),
          el("div", { class: "value", text: String(value) }),
        ])
      );
    });

    const protoCard = el("div", { class: "stat-card proto-breakdown" }, [
      el("div", { class: "label", text: "Protocol breakdown" }),
    ]);
    const max = Math.max(...Object.values(s.proto_counts));
    Object.entries(s.proto_counts)
      .sort((a, b) => b[1] - a[1])
      .forEach(([proto, count]) => {
        const row = el("div", { class: "proto-bar-row" }, [
          el("div", { class: "proto-label", text: proto }),
          el("div", { class: "proto-bar-track" }, [
            el("div", { class: "proto-bar-fill", style: `width:${(count / max) * 100}%` }),
          ]),
          el("div", { class: "proto-bar-count", text: String(count) }),
        ]);
        protoCard.appendChild(row);
      });
    grid.appendChild(protoCard);

    if (s.top_talkers && s.top_talkers.length) {
      const talkersCard = el("div", { class: "stat-card proto-breakdown" }, [
        el("div", { class: "label", text: "Top talkers (by bytes)" }),
      ]);
      const maxBytes = Math.max(...s.top_talkers.map((t) => t.bytes));
      s.top_talkers.forEach((tk) => {
        talkersCard.appendChild(
          el("div", { class: "proto-bar-row" }, [
            el("div", { class: "proto-label", text: tk.ip }),
            el("div", { class: "proto-bar-track" }, [
              el("div", { class: "proto-bar-fill", style: `width:${(tk.bytes / maxBytes) * 100}%` }),
            ]),
            el("div", { class: "proto-bar-count", text: tk.bytes + " B" }),
          ])
        );
      });
      grid.appendChild(talkersCard);
    }
  }

  // ---------- SIP Call Flow ----------
  async function loadSip() {
    const data = await fetchJSON(`/api/analysis/${state.analysisId}/sip`);
    state.calls = data.calls || [];
    const sel = $("#callSelect");
    sel.innerHTML = "";
    if (state.calls.length === 0) {
      sel.appendChild(el("option", { text: "No SIP calls detected" }));
      $("#callflowSvg").innerHTML = "";
      $("#callflowMeta").textContent = "";
      return;
    }
    state.calls.forEach((c, i) => {
      const label = `${c.call_id.slice(0, 24)} — ${c.final_status || c.messages[0].label} (${c.message_count} msgs)`;
      sel.appendChild(el("option", { value: String(i), text: label }));
    });
    sel.onchange = () => renderCallFlow(state.calls[Number(sel.value)]);
    renderCallFlow(state.calls[0]);
  }

  function renderCallFlow(call) {
    const metaParts = [
      `From: ${call.from_hdr || "?"}`,
      `To: ${call.to_hdr || "?"}`,
      `Duration: ${call.duration_sec}s`,
    ];
    if (call.post_dial_delay_sec != null) metaParts.push(`Post-dial delay: ${call.post_dial_delay_sec}s`);
    if (call.retransmission_count) metaParts.push(`⚠ ${call.retransmission_count} retransmission(s)`);
    if (call.user_agent) metaParts.push(`UA: ${call.user_agent}`);
    $("#callflowMeta").textContent = metaParts.join("  |  ");

    const svg = $("#callflowSvg");
    svg.innerHTML = "";
    const participants = call.participants;
    const colWidth = 260;
    const leftMargin = 90;
    const topMargin = 50;
    const rowHeight = 46;
    const width = leftMargin + colWidth * participants.length + 40;
    const rows = call.messages.length + (call.media_endpoints.length ? 1 : 0);
    const height = topMargin + rowHeight * (rows + 1) + 30;

    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("width", width);
    svg.setAttribute("height", height);

    const ns = "http://www.w3.org/2000/svg";
    const mk = (tag, attrs) => {
      const e = document.createElementNS(ns, tag);
      for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
      return e;
    };

    const colX = (i) => leftMargin + colWidth * i + colWidth / 2;

    // participant headers + lifelines
    participants.forEach((p, i) => {
      const x = colX(i);
      const box = mk("rect", {
        x: x - 85, y: 8, width: 170, height: 30, rx: 5,
        fill: "#171f2a", stroke: "#223041",
      });
      svg.appendChild(box);
      const label = mk("text", {
        x, y: 27, "text-anchor": "middle", fill: "#e6edf3",
        "font-family": "JetBrains Mono, monospace", "font-size": "11.5",
      });
      label.textContent = p;
      svg.appendChild(label);

      const line = mk("line", {
        x1: x, y1: 40, x2: x, y2: height - 20,
        stroke: "#223041", "stroke-width": 1.5, "stroke-dasharray": "3,4",
      });
      svg.appendChild(line);
    });

    // messages
    let y = topMargin + 20;
    call.messages.forEach((m) => {
      const fromIdx = participants.indexOf(m.src);
      const toIdx = participants.indexOf(m.dst);
      const x1 = colX(fromIdx);
      const x2 = colX(toIdx);
      const isRequest = m.is_request;
      const color = m.is_retransmission ? "#ef6a5f" : (isRequest ? "#4dd8c0" : "#f2b134");
      const dash = m.is_retransmission ? "2,3" : (isRequest ? "none" : "5,4");

      const markerId = isRequest ? "arrow-req" : "arrow-res";
      const line = mk("line", {
        x1, y1: y, x2, y2: y,
        stroke: color, "stroke-width": 1.8, "stroke-dasharray": dash,
        "marker-end": `url(#${markerId})`,
      });
      svg.appendChild(line);

      const midX = (x1 + x2) / 2;
      const label = mk("text", {
        x: midX, y: y - 7, "text-anchor": "middle", fill: color,
        "font-family": "JetBrains Mono, monospace", "font-size": "11", "font-weight": "600",
      });
      label.textContent = (m.is_retransmission ? "↻ retrans: " : "") + m.label;
      svg.appendChild(label);

      const tlabel = mk("text", {
        x: 8, y: y + 3, fill: "#4d5c6c",
        "font-family": "JetBrains Mono, monospace", "font-size": "9.5",
      });
      tlabel.textContent = `t+${m.time_rel.toFixed(2)}s`;
      svg.appendChild(tlabel);

      // clickable hitbox
      const hit = mk("rect", { x: Math.min(x1, x2), y: y - 16, width: Math.abs(x2 - x1) || 1, height: 24, fill: "transparent" });
      hit.style.cursor = "pointer";
      hit.addEventListener("click", () => {
        activateTab("packets");
        setTimeout(() => selectPacketByFrame(m.frame), 150);
      });
      svg.appendChild(hit);

      y += rowHeight;
    });

    // RTP media band
    if (call.media_endpoints.length) {
      const matched = state.rtpStreams.filter((rs) => {
        const a = `${rs.src}:${rs.sport}`, b = `${rs.dst}:${rs.dport}`;
        return call.media_endpoints.some((ep) => ep === a || ep === b);
      });
      const leftIdx = 0, rightIdx = participants.length - 1;
      const x1 = colX(leftIdx), x2 = colX(rightIdx);
      const band = mk("rect", {
        x: Math.min(x1, x2), y: y - 14, width: Math.abs(x2 - x1), height: 20,
        fill: "#1f3a2e", stroke: "#2c7d70", rx: 4,
      });
      svg.appendChild(band);
      const label = mk("text", {
        x: (x1 + x2) / 2, y: y, "text-anchor": "middle", fill: "#4dd8c0",
        "font-family": "JetBrains Mono, monospace", "font-size": "10.5", "font-weight": "600",
      });
      label.textContent = matched.length
        ? `RTP media — ${matched.map((m) => m.codec).join(", ")} (${matched.reduce((a, m) => a + m.packet_count, 0)} pkts)`
        : "RTP media (negotiated)";
      svg.appendChild(label);
    }

    // arrow marker defs
    const defs = mk("defs", {});
    [["arrow-req", "#4dd8c0"], ["arrow-res", "#f2b134"]].forEach(([id, color]) => {
      const marker = mk("marker", {
        id, viewBox: "0 0 10 10", refX: "9", refY: "5",
        markerWidth: "7", markerHeight: "7", orient: "auto-start-reverse",
      });
      const path = mk("path", { d: "M0,0 L10,5 L0,10 z", fill: color });
      marker.appendChild(path);
      defs.appendChild(marker);
    });
    svg.insertBefore(defs, svg.firstChild);
  }

  // ---------- RTP Streams ----------
  async function loadRtp() {
    const data = await fetchJSON(`/api/analysis/${state.analysisId}/rtp`);
    state.rtpStreams = data.streams || [];
    const tbody = $("#rtpTable tbody");
    tbody.innerHTML = "";
    state.rtpStreams.forEach((s) => {
      tbody.appendChild(
        el("tr", {}, [
          el("td", { text: String(s.id) }),
          el("td", { text: `${s.src}:${s.sport}` }),
          el("td", { text: `${s.dst}:${s.dport}` }),
          el("td", { text: s.ssrc }),
          el("td", { text: String(s.payload_type) }),
          el("td", { text: s.codec }),
          el("td", { text: String(s.packet_count) }),
          el("td", { text: s.duration_sec + "s" }),
          el("td", { text: String(s.avg_pps) }),
          el("td", { text: s.jitter_ms + " ms" }),
          el("td", { text: s.loss_pct + "%" }),
          el("td", { text: String(s.out_of_order) }),
          el("td", { text: s.mos_estimate != null ? String(s.mos_estimate) : "—" }),
        ])
      );
    });
    if (state.rtpStreams.length === 0) {
      tbody.appendChild(el("tr", {}, [el("td", { colspan: "13", text: "No RTP streams detected." })]));
    }
  }

  // ---------- Conversations ----------
  async function loadConversations() {
    const data = await fetchJSON(`/api/analysis/${state.analysisId}/conversations`);
    const talkersBody = $("#talkersTable tbody");
    talkersBody.innerHTML = "";
    (data.top_talkers || []).forEach((t) => {
      talkersBody.appendChild(
        el("tr", {}, [
          el("td", { text: t.ip }),
          el("td", { text: String(t.packets) }),
          el("td", { text: String(t.bytes) }),
          el("td", { text: String(t.peer_count) }),
        ])
      );
    });
    const convBody = $("#convTable tbody");
    convBody.innerHTML = "";
    (data.ip_conversations || []).forEach((c) => {
      convBody.appendChild(
        el("tr", {}, [
          el("td", { text: c.a }),
          el("td", { text: c.b }),
          el("td", { text: String(c.packets) }),
          el("td", { text: String(c.bytes) }),
          el("td", { text: c.duration_sec + "s" }),
          el("td", { text: String(c.avg_bps) }),
        ])
      );
    });
  }

  // ---------- DNS ----------
  async function loadDns() {
    const data = await fetchJSON(`/api/analysis/${state.analysisId}/dns`);
    const tbody = $("#dnsTable tbody");
    tbody.innerHTML = "";
    (data.records || []).forEach((r) => {
      tbody.appendChild(
        el("tr", {}, [
          el("td", { text: String(r.frame) }),
          el("td", { text: r.src }),
          el("td", { text: r.dst }),
          el("td", { text: r.is_response ? "Response" : "Query" }),
          el("td", { text: r.query_name || "—" }),
          el("td", { text: (r.answers || []).join(", ") || "—" }),
        ])
      );
    });
    if (!(data.records || []).length) {
      tbody.appendChild(el("tr", {}, [el("td", { colspan: "6", text: "No DNS traffic detected." })]));
    }
  }

  // ---------- TCP ----------
  async function loadTcp() {
    const data = await fetchJSON(`/api/analysis/${state.analysisId}/tcp`);
    const tbody = $("#tcpTable tbody");
    tbody.innerHTML = "";
    (data.streams || []).forEach((s) => {
      const tr = el("tr", {}, [
        el("td", { text: s.a }),
        el("td", { text: s.b }),
        el("td", { text: String(s.packets) }),
        el("td", { text: String(s.bytes) }),
        el("td", { text: String(s.syn) }),
        el("td", { text: String(s.fin) }),
        el("td", { text: String(s.rst) }),
        el("td", { text: String(s.retransmissions) }),
        el("td", { text: s.duration_sec + "s" }),
      ]);
      if (s.retransmissions > 0) tr.style.color = "#f2b134";
      tbody.appendChild(tr);
    });
    if (!(data.streams || []).length) {
      tbody.appendChild(el("tr", {}, [el("td", { colspan: "9", text: "No TCP streams detected." })]));
    }
  }

  // ---------- Other (TLS / ARP / ICMP) ----------
  async function loadOther() {
    const data = await fetchJSON(`/api/analysis/${state.analysisId}/other`);

    const tlsBody = $("#tlsTable tbody");
    tlsBody.innerHTML = "";
    (data.tls || []).forEach((r) => {
      tlsBody.appendChild(
        el("tr", {}, [
          el("td", { text: String(r.frame) }),
          el("td", { text: `${r.src}:${r.sport}` }),
          el("td", { text: `${r.dst}:${r.dport}` }),
          el("td", { text: r.version }),
          el("td", { text: r.sni || "—" }),
        ])
      );
    });
    if (!(data.tls || []).length) {
      tlsBody.appendChild(el("tr", {}, [el("td", { colspan: "5", text: "No TLS handshakes detected." })]));
    }

    const arpBody = $("#arpTable tbody");
    arpBody.innerHTML = "";
    (data.arp || []).forEach((r) => {
      arpBody.appendChild(
        el("tr", {}, [
          el("td", { text: String(r.frame) }),
          el("td", { text: r.op }),
          el("td", { text: r.sender_ip }),
          el("td", { text: r.sender_mac }),
          el("td", { text: r.target_ip }),
          el("td", { text: r.target_mac }),
        ])
      );
    });
    if (!(data.arp || []).length) {
      arpBody.appendChild(el("tr", {}, [el("td", { colspan: "6", text: "No ARP traffic detected." })]));
    }

    const icmpBody = $("#icmpTable tbody");
    icmpBody.innerHTML = "";
    (data.icmp || []).forEach((r) => {
      icmpBody.appendChild(
        el("tr", {}, [
          el("td", { text: String(r.frame) }),
          el("td", { text: r.src }),
          el("td", { text: r.dst }),
          el("td", { text: r.description }),
          el("td", { text: String(r.code) }),
        ])
      );
    });
    if (!(data.icmp || []).length) {
      icmpBody.appendChild(el("tr", {}, [el("td", { colspan: "5", text: "No ICMP traffic detected." })]));
    }
  }

  // ---------- Packet list ----------
  let searchDebounce;
  $("#packetSearch").addEventListener("input", () => {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(() => loadPackets(), 250);
  });
  $("#protoFilter").addEventListener("change", () => loadPackets());

  async function loadPacketsInitial() {
    // populate protocol filter from summary
    const protoSel = $("#protoFilter");
    protoSel.innerHTML = '<option value="">All protocols</option>';
    Object.keys(state.summary.proto_counts).forEach((p) => {
      protoSel.appendChild(el("option", { value: p, text: p }));
    });
    await loadPackets();
  }

  async function loadPackets() {
    const q = $("#packetSearch").value.trim();
    const proto = $("#protoFilter").value;
    const params = new URLSearchParams({ q, proto, offset: 0, limit: 1000 });
    try {
      const data = await fetchJSON(`/api/analysis/${state.analysisId}/packets?${params}`);
      state.packetsCache = data.packets || [];
      state.packetTotal = data.total || 0;
      renderPacketTable();
    } catch (err) {
      setStatus("Failed to load packets: " + err.message, "error");
    }
  }

  function renderPacketTable() {
    const tbody = $("#packetTable tbody");
    tbody.innerHTML = "";
    $("#packetCount").textContent = `${state.packetTotal} packet(s)` +
      (state.packetsCache.length < state.packetTotal ? ` (showing first ${state.packetsCache.length})` : "");

    const frag = document.createDocumentFragment();
    state.packetsCache.forEach((p) => {
      const tr = el("tr", { "data-frame": String(p.frame) }, [
        el("td", { text: String(p.frame) }),
        el("td", { text: p.time_rel.toFixed(6) }),
        el("td", { text: p.src }),
        el("td", { text: p.dst }),
        el("td", {}, [el("span", { class: `tag tag-${p.proto}`, text: p.proto })]),
        el("td", { text: String(p.length) }),
        el("td", { text: p.info }),
      ]);
      tr.addEventListener("click", () => selectPacketRow(tr, p.frame));
      frag.appendChild(tr);
    });
    tbody.appendChild(frag);
  }

  async function selectPacketRow(tr, frameNo) {
    document.querySelectorAll("#packetTable tbody tr").forEach((r) => r.classList.remove("selected"));
    tr.classList.add("selected");
    tr.scrollIntoView({ block: "nearest" });
    await showPacketDetail(frameNo);
  }

  async function selectPacketByFrame(frameNo) {
    const row = document.querySelector(`#packetTable tbody tr[data-frame="${frameNo}"]`);
    if (row) {
      await selectPacketRow(row, frameNo);
    } else {
      await showPacketDetail(frameNo);
    }
  }

  async function showPacketDetail(frameNo) {
    const panel = $("#packetDetail");
    let data;
    try {
      data = await fetchJSON(`/api/analysis/${state.analysisId}/packet/${frameNo}`);
    } catch (err) {
      panel.innerHTML = `<div class="packet-detail-empty">Failed to load packet: ${err.message}</div>`;
      return;
    }
    if (!data.frame) {
      panel.innerHTML = '<div class="packet-detail-empty">Packet not found.</div>';
      return;
    }
    const f = data.frame;
    panel.innerHTML = "";
    panel.appendChild(el("h3", { text: `Frame ${f.frame}` }));
    const kv = el("div", { class: "kv" });
    const rows = [
      ["Time", f.time_rel.toFixed(6) + "s"],
      ["Source", `${f.src}${f.sport ? ":" + f.sport : ""}`],
      ["Dest", `${f.dst}${f.dport ? ":" + f.dport : ""}`],
      ["Protocol", f.proto],
      ["Length", f.length + " bytes"],
      ["Info", f.info],
    ];
    rows.forEach(([k, v]) => {
      kv.appendChild(el("div", { text: k }));
      kv.appendChild(el("div", { text: v }));
    });
    panel.appendChild(kv);
    panel.appendChild(el("h3", { text: "Raw bytes" }));
    panel.appendChild(el("div", { class: "hexdump", text: data.hexdump }));
  }
})();
