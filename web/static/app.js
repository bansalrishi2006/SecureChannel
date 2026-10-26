let sessionId = null;
const variant = document.querySelector("#variant");
const message = document.querySelector("#message");
const sendButton = document.querySelector("#send");
const attackButtons = [...document.querySelectorAll("[data-attack]")];
const attackResults = document.querySelector("#attack-results");
const sessionStatus = document.querySelector("#session-status");
const sentVariants = new Set();

async function post(path, body) {
  const response = await fetch(path, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function updateAttackAvailability() {
  for (const button of attackButtons) button.disabled = !sessionId || !sentVariants.has(variant.value) || button.dataset.busy === "true";
}

async function startSession() {
  try {
    const data = await post("/api/session", {});
    sessionId = data.session_id;
    sessionStatus.textContent = "SESSION READY · LOOPBACK";
    updateAttackAvailability();
  } catch (error) { sessionStatus.textContent = error.message; }
}

sendButton.addEventListener("click", async () => {
  if (!sessionId) return;
  sendButton.disabled = true;
  try {
    const data = await post("/api/send", {session_id:sessionId, variant:variant.value, message:message.value});
    document.querySelector("#echo").textContent = data.echo;
    document.querySelector("#wire").textContent = `Raw frame (base64):\n${data.frame_base64}\n\nDecoded JSON frame:\n${JSON.stringify(data.frame_json, null, 2)}`;
    sentVariants.add(variant.value);
    renderHandshake(data.handshake);
    attackResults.innerHTML = '<p class="result empty">Message sent. Select an attack to run against this channel.</p>';
    updateAttackAvailability();
  } catch (error) { document.querySelector("#echo").textContent = error.message; }
  finally { sendButton.disabled = false; }
});

variant.addEventListener("change", () => {
  attackResults.innerHTML = `<p class="result empty">${sentVariants.has(variant.value) ? "This channel has a sent message. Choose an attack." : "Send a message on this channel to enable attacks."}</p>`;
  updateAttackAvailability();
});

function renderHandshake(handshake) {
  const secure = variant.value === "secure";
  const cipher = handshake.selected_cipher;
  const steps = [
    ["Client Hello", "client offered supported ciphers"],
    ["Server Hello", `cipher: ${cipher}`],
    ["Certificate check", handshake.certificate_validated ? "certificate validated" : "validation disabled"],
    ["Finished", handshake.transcript_hmac_enforced ? "transcript HMAC enforced" : "transcript HMAC disabled"],
    ["Data frame sent", "encrypted application data"],
  ];
  const good = secure && handshake.certificate_validated && handshake.transcript_hmac_enforced && cipher.includes("HYBRID");
  document.querySelector("#protocol-steps").innerHTML = steps.map(([title, detail], index) => {
    const status = good ? "secure" : (index === 2 || index === 3 || index === 1 ? "exposed" : "caution");
    return `<li class="${status}"><span>${escapeHtml(title)}</span><small>${escapeHtml(detail)}</small></li>`;
  }).join("");
}

for (const button of attackButtons) {
  button.addEventListener("click", async () => {
    const name = button.dataset.attack;
    button.dataset.busy = "true";
    updateAttackAvailability();
    button.textContent = "Running…";
    try {
      const data = await post(`/api/attack/${name}`, {session_id:sessionId, variant:variant.value});
      const successful = data.outcome === "succeeded";
      let html = `<h3>${successful ? "⚠" : "✓"} ${escapeHtml(name.toUpperCase())} ${successful ? "succeeded" : "blocked"}</h3><p>${escapeHtml(data.details)}</p>`;
      if (name === "mitm" && successful) html += `<p>Captured payload:</p><span class="plaintext">${escapeHtml(data.plaintext ?? "No payload captured")}</span>`;
      const card = document.createElement("div");
      card.className = `result ${successful ? "succeeded" : "blocked"}`;
      card.innerHTML = html;
      attackResults.prepend(card);
    } catch (error) {
      const card = document.createElement("div"); card.className = "result blocked"; card.textContent = error.message; attackResults.prepend(card);
    } finally {
      button.dataset.busy = "false";
      button.textContent = button.dataset.attack === "mitm" ? "Launch MITM" : button.dataset.attack === "cert-spoof" ? "Cert Spoof" : button.dataset.attack[0].toUpperCase() + button.dataset.attack.slice(1);
      updateAttackAvailability();
    }
  });
}

function escapeHtml(value) { return String(value).replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char])); }
startSession();
