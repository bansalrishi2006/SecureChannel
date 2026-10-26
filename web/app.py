from __future__ import annotations

import base64
import json
import struct
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from attack_suite.mitm import MITMAttack
from attack_suite.report import AttackTarget
from insecure_variant.client import InsecureClient
from insecure_variant.server import InsecureServer
from secure_core.client import SecureClient
from secure_core.pki import Identity, TrustStore, make_test_pki
from secure_core.server import SecureServer


MAX_FRAME_SIZE = 65536
SESSION_TTL_SECONDS = 10 * 60
_sessions: dict[str, "WebSession"] = {}
_sessions_lock = threading.RLock()


@dataclass
class WebSession:
    ca_cert_pem: bytes
    client_identity: Identity
    trust: TrustStore
    client_cls: dict[str, type]
    servers: dict[str, SecureServer]
    last_messages: dict[str, bytes]
    last_used: float


def _stop_session(session: WebSession) -> None:
    for srv in session.servers.values():
        srv.stop()


def _sweep_sessions(now: float | None = None) -> None:
    now = time.monotonic() if now is None else now
    expired: list[WebSession] = []
    with _sessions_lock:
        for session_id, session in list(_sessions.items()):
            if now - session.last_used > SESSION_TTL_SECONDS:
                expired.append(_sessions.pop(session_id))
    for session in expired:
        _stop_session(session)


def _get_session(session_id: str | None) -> WebSession | None:
    if not isinstance(session_id, str):
        return None
    _sweep_sessions()
    with _sessions_lock:
        session = _sessions.get(session_id)
        if session is not None:
            session.last_used = time.monotonic()
        return session


def _variant(value: object) -> str | None:
    return value if value in ("secure", "insecure") else None


app = Flask(__name__, static_folder="static")


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.post("/api/session")
def create_session():
    _sweep_sessions()
    ca, server_identity, client_identity, trust = make_test_pki()
    secure_srv = SecureServer("127.0.0.1", 0, server_identity, trust)
    insecure_srv = InsecureServer("127.0.0.1", 0, server_identity, trust)
    try:
        secure_srv.start()
        insecure_srv.start()
    except Exception:
        secure_srv.stop()
        insecure_srv.stop()
        raise
    session_id = uuid.uuid4().hex
    session = WebSession(
        ca_cert_pem=ca.cert_pem,
        client_identity=client_identity,
        trust=trust,
        client_cls={"secure": SecureClient, "insecure": InsecureClient},
        servers={"secure": secure_srv, "insecure": insecure_srv},
        last_messages={},
        last_used=time.monotonic(),
    )
    with _sessions_lock:
        _sessions[session_id] = session
    return jsonify({"session_id": session_id})


@app.post("/api/send")
def send_message():
    body = request.get_json(silent=True) or {}
    session = _get_session(body.get("session_id"))
    variant = _variant(body.get("variant"))
    message = body.get("message")
    if session is None:
        return jsonify({"error": "unknown or expired session_id"}), 400
    if variant is None:
        return jsonify({"error": 'variant must be "secure" or "insecure"'}), 400
    if not isinstance(message, str):
        return jsonify({"error": "message must be a string"}), 400
    plaintext = message.encode("utf-8")
    if len(plaintext) > MAX_FRAME_SIZE:
        return jsonify({"error": "message exceeds the 64 KB frame limit"}), 400

    client = session.client_cls[variant](
        "127.0.0.1", session.servers[variant].port, session.client_identity, session.trust
    )
    try:
        # send_message returns the same application frame passed to send_frame;
        # serialize it with send_frame's exact JSON separators and length prefix.
        client.connect()
        wire_payload = client.send_message(plaintext)
        echoed = client.receive_message().decode("utf-8")
        session.last_messages[variant] = plaintext
        encoded_frame = json.dumps(wire_payload, separators=(",", ":")).encode("utf-8")
        frame = struct.pack("!I", len(encoded_frame)) + encoded_frame
        return jsonify({
            "echo": echoed,
            "frame_base64": base64.b64encode(frame).decode("ascii"),
            "frame_json": wire_payload,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502
    finally:
        client.close()


@app.post("/api/attack/mitm")
def attack_mitm():
    body = request.get_json(silent=True) or {}
    session = _get_session(body.get("session_id"))
    variant = _variant(body.get("variant"))
    if session is None:
        return jsonify({"error": "unknown or expired session_id"}), 400
    if variant is None:
        return jsonify({"error": 'variant must be "secure" or "insecure"'}), 400
    if variant not in session.last_messages:
        return jsonify({"error": "send a message on this variant before launching MITM"}), 400
    attack = MITMAttack()
    target = AttackTarget(
        variant=variant,
        host="127.0.0.1",
        port=session.servers[variant].port,
        ca_cert_pem=session.ca_cert_pem,
        client_identity=session.client_identity,
        client_cls=session.client_cls[variant],
    )
    result = attack.run(target, capture_payload=session.last_messages[variant])
    payload = {
        "outcome": result.outcome,
        "details": result.details,
    }
    if result.outcome == "succeeded" and attack.captured_payload is not None:
        payload["plaintext"] = attack.captured_payload.decode("utf-8", errors="replace")
    return jsonify(payload)


@app.get("/api/report/<variant>")
def get_report(variant: str):
    if variant not in ("secure_core", "insecure_variant"):
        return jsonify({"error": "unknown report variant"}), 404
    path = Path(__file__).resolve().parent.parent / "docs" / f"{variant}_attack_report.json"
    if not path.is_file():
        return jsonify({"error": "report not found"}), 404
    return app.response_class(path.read_text(encoding="utf-8"), mimetype="application/json")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
