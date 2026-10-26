from __future__ import annotations

import pytest

from web import app as web_app


@pytest.fixture
def client():
    web_app.app.config.update(TESTING=True)
    with web_app.app.test_client() as test_client:
        yield test_client
    with web_app._sessions_lock:
        sessions = list(web_app._sessions.values())
        web_app._sessions.clear()
    for session in sessions:
        web_app._stop_session(session)


def create_session(client):
    response = client.post("/api/session", json={})
    assert response.status_code == 200
    return response.get_json()["session_id"]


def test_session_create(client):
    session_id = create_session(client)
    assert session_id
    session = web_app._sessions[session_id]
    assert set(session.servers) == {"secure", "insecure"}
    assert session.servers["secure"].port != session.servers["insecure"].port


@pytest.mark.parametrize("variant", ["secure", "insecure"])
def test_send_echo_and_wire_frame(client, variant):
    session_id = create_session(client)
    response = client.post("/api/send", json={
        "session_id": session_id,
        "variant": variant,
        "message": "hello wire",
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data["echo"] == "hello wire"
    assert data["frame_base64"]
    assert data["frame_json"]["type"] == "data"
    assert "ciphertext" in data["frame_json"]
    assert data["frame_json"]["ciphertext"] != "hello wire"
    handshake = data["handshake"]
    assert set(handshake) == {"selected_cipher", "certificate_validated", "transcript_hmac_enforced"}


def test_send_handshake_summary_differs_by_variant(client):
    summaries = {}
    for variant in ("secure", "insecure"):
        session_id = create_session(client)
        response = client.post("/api/send", json={"session_id": session_id, "variant": variant, "message": "handshake"})
        assert response.status_code == 200
        summaries[variant] = response.get_json()["handshake"]
    assert summaries["secure"]["selected_cipher"] == "HYBRID_X25519_MLKEM768_AES256_GCM"
    assert summaries["insecure"]["selected_cipher"] == "X25519_ONLY_AES256_GCM"
    assert summaries["secure"]["certificate_validated"] is True
    assert summaries["insecure"]["certificate_validated"] is False
    assert summaries["secure"]["transcript_hmac_enforced"] is True
    assert summaries["insecure"]["transcript_hmac_enforced"] is False


@pytest.mark.parametrize(("variant", "outcome"), [("secure", "blocked"), ("insecure", "succeeded")])
def test_mitm_result_shape(client, variant, outcome):
    session_id = create_session(client)
    client.post("/api/send", json={"session_id": session_id, "variant": variant, "message": "capture me"})
    response = client.post("/api/attack/mitm", json={"session_id": session_id, "variant": variant})
    assert response.status_code == 200
    data = response.get_json()
    assert data["outcome"] == outcome
    assert isinstance(data["details"], str)
    if outcome == "succeeded":
        assert data["plaintext"] == "capture me"
    else:
        assert "plaintext" not in data


@pytest.mark.parametrize("attack", ["replay", "downgrade", "cert-spoof", "dos"])
@pytest.mark.parametrize("variant,outcome", [("secure", "blocked"), ("insecure", "succeeded")])
def test_additional_attack_result_shape(client, attack, variant, outcome):
    session_id = create_session(client)
    sent = client.post("/api/send", json={"session_id": session_id, "variant": variant, "message": "attack target"})
    assert sent.status_code == 200
    response = client.post(f"/api/attack/{attack}", json={"session_id": session_id, "variant": variant})
    assert response.status_code == 200
    data = response.get_json()
    assert data["outcome"] == outcome
    assert isinstance(data["details"], str)
    assert "plaintext" not in data


def test_rejects_message_larger_than_frame_limit(client):
    session_id = create_session(client)
    response = client.post("/api/send", json={
        "session_id": session_id,
        "variant": "insecure",
        "message": "x" * (web_app.MAX_FRAME_SIZE + 1),
    })
    assert response.status_code == 400
