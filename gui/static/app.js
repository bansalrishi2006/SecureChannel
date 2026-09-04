const wsStatus = document.getElementById("ws-status");
const eventLog = document.getElementById("event-log");
const variantSelect = document.getElementById("variant");
const sequenceSvg = document.getElementById("sequence");
const keyBody = document.querySelector("#key-panel tbody");
const attackBody = document.querySelector("#attack-results tbody");
const reportBody = document.querySelector("#report-table tbody");

const sequenceEvents = [];
const keyRows = new Map();
const attackRows = new Map();

function classify(type) {
  if (type.startsWith("handshake")) return "log-handshake";
  if (type.startsWith("crypto")) return "log-crypto";
  if (type.startsWith("session")) return "log-session";
  if (type.startsWith("attack")) return "log-attack";
  return "";
}

function appendLog(event) {
  const entry = document.createElement("div");
  entry.className = `log-entry ${classify(event.event_type)}`;
  entry.textContent = `[${event.timestamp}] ${event.event_type} ${JSON.stringify(event)}`;
  eventLog.appendChild(entry);
  eventLog.scrollTop = eventLog.scrollHeight;
}

function renderSequence() {
  sequenceSvg.innerHTML = "";
  const leftX = 220;
  const rightX = 680;
  const topY = 30;
  const laneBottom = 340;

  const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
  const marker = document.createElementNS("http://www.w3.org/2000/svg", "marker");
  marker.setAttribute("id", "arrow");
  marker.setAttribute("viewBox", "0 0 10 10");
  marker.setAttribute("refX", "9");
  marker.setAttribute("refY", "5");
  marker.setAttribute("markerWidth", "6");
  marker.setAttribute("markerHeight", "6");
  marker.setAttribute("orient", "auto-start-reverse");
  const arrowPath = document.createElementNS("http://www.w3.org/2000/svg", "path");
  arrowPath.setAttribute("d", "M 0 0 L 10 5 L 0 10 z");
  arrowPath.setAttribute("fill", "#2f3a4b");
  marker.appendChild(arrowPath);
  defs.appendChild(marker);
  sequenceSvg.appendChild(defs);

  [[leftX, "Client"], [rightX, "Server"]].forEach(([x, label]) => {
    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("x", x);
    text.setAttribute("y", 20);
    text.setAttribute("text-anchor", "middle");
    text.textContent = label;
    sequenceSvg.appendChild(text);

    const lane = document.createElementNS("http://www.w3.org/2000/svg", "line");
    lane.setAttribute("x1", x);
    lane.setAttribute("y1", topY);
    lane.setAttribute("x2", x);
    lane.setAttribute("y2", laneBottom);
    lane.setAttribute("stroke", "#7a8598");
    lane.setAttribute("stroke-dasharray", "5 5");
    sequenceSvg.appendChild(lane);
  });

  sequenceEvents.slice(-8).forEach((event, index) => {
    const y = 55 + index * 34;
    const toServer = event.event_type.includes("send.client_hello") || event.event_type.includes("send.finished");
    const toClient = event.event_type.includes("send.server_hello") || event.event_type.includes("send.handshake_complete");
    if (!toServer && !toClient) return;

    const x1 = toServer ? leftX : rightX;
    const x2 = toServer ? rightX : leftX;
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", x1);
    line.setAttribute("y1", y);
    line.setAttribute("x2", x2);
    line.setAttribute("y2", y);
    line.setAttribute("stroke", "#2f3a4b");
    line.setAttribute("marker-end", "url(#arrow)");
    sequenceSvg.appendChild(line);

    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", (x1 + x2) / 2);
    label.setAttribute("y", y - 5);
    label.setAttribute("text-anchor", "middle");
    let frame = {};
    if (event.frame_json) {
      try {
        frame = JSON.parse(event.frame_json);
      } catch {
        frame = {};
      }
    }
    const cipher = frame.selected_cipher || event.selected_cipher || "";
    const kyber = cipher.includes("HYBRID") ? "kyber" : "";
    label.textContent = `${event.frame_type || event.event_type} ${cipher} ${kyber}`.trim();
    sequenceSvg.appendChild(label);
  });
}

function updateKeys(event) {
  const key = event.connection_id;
  keyRows.set(key, event);
  keyBody.innerHTML = "";
  Array.from(keyRows.values()).slice(-8).forEach((row) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${row.connection_id}</td><td>${row.variant}</td><td>${row.selected_cipher || ""}</td><td>${row.c2s_key_fingerprint || ""}</td><td>${row.s2c_key_fingerprint || ""}</td><td>${row.transcript_key_fingerprint || ""}</td>`;
    keyBody.appendChild(tr);
  });
}

function updateAttackResult(event) {
  const key = `${event.attack}:${event.target_variant}`;
  attackRows.set(key, event);
  attackBody.innerHTML = "";
  Array.from(attackRows.values()).forEach((row) => {
    const tr = document.createElement("tr");
    const cls = row.outcome === "blocked" ? "result-blocked" : "result-succeeded";
    tr.innerHTML = `<td>${row.attack}</td><td>${row.target_variant}</td><td class="${cls}">${row.outcome}</td><td>${row.details || ""}</td>`;
    attackBody.appendChild(tr);
  });
}

function handleEvent(event) {
  appendLog(event);
  if (event.event_type.startsWith("handshake")) {
    sequenceEvents.push(event);
    renderSequence();
  }
  if (event.event_type === "crypto.key_schedule_derived") {
    updateKeys(event);
  }
  if (event.event_type === "attack.result") {
    updateAttackResult(event);
  }
}

async function post(path, body = null) {
  await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : null,
  });
}

document.getElementById("run-demo").addEventListener("click", () => post("/api/run-demo"));
document.querySelectorAll(".attack-buttons button").forEach((button) => {
  button.addEventListener("click", () => {
    post("/api/run-attack", {
      attack: button.dataset.attack,
      variant: variantSelect.value,
    });
  });
});

async function loadReports() {
  const data = await fetch("/api/last-report").then((r) => r.json());
  reportBody.innerHTML = "";
  Object.entries(data).forEach(([variant, report]) => {
    (report.results || []).forEach((result) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${variant}</td><td>${result.attack}</td><td>${result.outcome}</td><td>${result.details}</td>`;
      reportBody.appendChild(tr);
    });
  });
}

function connectWebSocket() {
  let backoffMs = 1000;
  const start = () => {
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${scheme}://${location.host}/ws/events`);

    ws.onopen = () => {
      wsStatus.textContent = "Connected";
      wsStatus.classList.remove("disconnected");
      wsStatus.classList.add("connected");
      backoffMs = 1000;
    };

    ws.onmessage = (msg) => {
      try {
        handleEvent(JSON.parse(msg.data));
      } catch {
        // ignore malformed frames
      }
    };

    ws.onclose = () => {
      wsStatus.textContent = "Disconnected";
      wsStatus.classList.remove("connected");
      wsStatus.classList.add("disconnected");
      setTimeout(start, backoffMs);
      backoffMs = Math.min(backoffMs * 2, 10000);
    };

    ws.onerror = () => ws.close();
  };

  start();
}

loadReports();
renderSequence();
connectWebSocket();
