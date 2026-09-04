from __future__ import annotations

from fastapi.testclient import TestClient

import gui.server as gui_server


client = TestClient(gui_server.app)


def test_get_root_returns_200():
    response = client.get("/")
    assert response.status_code == 200


def test_run_attack_valid_body_returns_started(monkeypatch):
    monkeypatch.setattr(gui_server, "_run_attack_background", lambda attack, variant: None)
    response = client.post("/api/run-attack", json={"attack": "mitm", "variant": "secure_core"})
    assert response.status_code == 200
    assert response.json()["status"] == "started"


def test_last_report_returns_existing_json():
    response = client.get("/api/last-report")
    assert response.status_code == 200
    body = response.json()
    assert "secure_core" in body
    assert "insecure_variant" in body
