let sessionId = null;
const variant = document.querySelector("#variant");
const message = document.querySelector("#message");
const sendButton = document.querySelector("#send");
const attackButton = document.querySelector("#attack");
const attackResult = document.querySelector("#attack-result");
const sessionStatus = document.querySelector("#session-status");

async function post(path, body) {
  const response = await fetch(path, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

async function startSession() {
  try {
    const data = await post("/api/session", {});
    sessionId = data.session_id;
    sessionStatus.textContent = "Private loopback session ready";
    attackButton.disabled = false;
  } catch (error) {
    sessionStatus.textContent = error.message;
  }
}

sendButton.addEventListener("click", async () => {
  if (!sessionId) return;
  sendButton.disabled = true;
  try {
    const data = await post("/api/send", {session_id:sessionId, variant:variant.value, message:message.value});
    document.querySelector("#echo").textContent = data.echo;
    document.querySelector("#wire").textContent = `Raw frame (base64):\n${data.frame_base64}\n\nDecoded JSON frame:\n${JSON.stringify(data.frame_json, null, 2)}`;
    attackResult.className = "result empty";
    attackResult.textContent = "Message sent. Launch MITM to test this message.";
  } catch (error) {
    document.querySelector("#echo").textContent = error.message;
  } finally { sendButton.disabled = false; }
});

attackButton.addEventListener("click", async () => {
  if (!sessionId) return;
  attackButton.disabled = true;
  attackButton.textContent = "Attacking…";
  attackResult.className = "result empty";
  attackResult.textContent = "The rogue server is attempting a handshake…";
  try {
    const data = await post("/api/attack/mitm", {session_id:sessionId, variant:variant.value});
    if (data.outcome === "succeeded") {
      attackResult.className = "result succeeded";
      attackResult.innerHTML = `<h3>✓ MITM succeeded — message exposed</h3><p>${escapeHtml(data.details)}</p><p>This is what an attacker on the wire could read:</p><span class="plaintext">${escapeHtml(data.plaintext ?? "No payload captured")}</span>`;
    } else {
      attackResult.className = "result blocked";
      attackResult.innerHTML = `<h3>✕ MITM blocked</h3><p>${escapeHtml(data.details)}</p><p>The message remained unreadable to the attacker.</p>`;
    }
  } catch (error) {
    attackResult.className = "result blocked";
    attackResult.textContent = error.message;
  } finally { attackButton.disabled = false; attackButton.textContent = "Launch MITM"; }
});

function escapeHtml(value) { return String(value).replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char])); }
startSession();
