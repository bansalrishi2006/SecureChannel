from __future__ import annotations

import asyncio
import json
import os
import threading
import time
import webbrowser
from pathlib import Path
from typing import Literal

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from attack_suite.cert_spoof import CertSpoofAttack
from attack_suite.dos import DoSAttack
from attack_suite.downgrade import DowngradeAttack
from attack_suite.mitm import MITMAttack
from attack_suite.replay import ReplayAttack
from attack_suite.report import AttackTarget, aggregate_reports
from demo.run_demo import run_demo
from insecure_variant.client import InsecureClient
from insecure_variant.server import InsecureServer
from secure_core.events import events
from secure_core.pki import make_test_pki
from secure_core.client import SecureClient
from secure_core.server import SecureServer

APP_HOST = "127.0.0.1"
APP_PORT = 8765
ROOT_DIR = Path(__file__).resolve().parents[1]
STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="SecureChannel GUI")


class AttackRequest(BaseModel):
    attack: Literal["mitm", "replay", "downgrade", "cert_spoof", "dos"]
    variant: Literal["secure_core", "insecure_variant"]


ATTACKS = {
    "mitm": MITMAttack,
    "replay": ReplayAttack,
    "downgrade": DowngradeAttack,
    "cert_spoof": CertSpoofAttack,
    "dos": DoSAttack,
}


def _run_in_repo(task) -> None:
    old = Path.cwd()
    try:
        os.chdir(ROOT_DIR)
        task()
    finally:
        os.chdir(old)


def _run_demo_background() -> None:
    _run_in_repo(run_demo)


def _run_attack_background(attack_name: str, variant: str) -> None:
    def _task() -> None:
        ca, server_id, client_id, trust = make_test_pki()
        secure = SecureServer("127.0.0.1", 0, server_id, trust)
        insecure = InsecureServer("127.0.0.1", 0, server_id, trust)
        secure.start()
        insecure.start()
        try:
            mapping = {
                "secure_core": (secure.port, SecureClient),
                "insecure_variant": (insecure.port, InsecureClient),
            }
            port, client_cls = mapping[variant]
            target = AttackTarget(
                variant=variant,
                host="127.0.0.1",
                port=port,
                ca_cert_pem=ca.cert_pem,
                client_identity=client_id,
                client_cls=client_cls,
            )
            attack = ATTACKS[attack_name]()
            result = attack.run(target)
            aggregate_reports(variant, [result], ROOT_DIR / "docs")
        finally:
            secure.stop()
            insecure.stop()

    _run_in_repo(_task)


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/app.js")
def js_asset():
    return FileResponse(STATIC_DIR / "app.js")


@app.get("/styles.css")
def css_asset():
    return FileResponse(STATIC_DIR / "styles.css")


@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await websocket.accept()
    q: asyncio.Queue[dict] = asyncio.Queue(maxsize=2048)
    loop = asyncio.get_running_loop()

    def callback(event: dict) -> None:
        def _enqueue() -> None:
            if q.full():
                return
            q.put_nowait(event)

        loop.call_soon_threadsafe(_enqueue)

    unsubscribe = events.subscribe(callback)
    try:
        while True:
            event = await q.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        return
    finally:
        unsubscribe()


@app.post("/api/run-demo")
def run_demo_endpoint():
    thread = threading.Thread(target=_run_demo_background, daemon=True)
    thread.start()
    return {"status": "started", "task": "full_demo"}


@app.post("/api/run-attack")
def run_attack_endpoint(request: AttackRequest):
    thread = threading.Thread(target=_run_attack_background, args=(request.attack, request.variant), daemon=True)
    thread.start()
    return {"status": "started", "attack": request.attack, "variant": request.variant}


@app.get("/api/last-report")
def last_report():
    payload: dict[str, dict] = {}
    for variant in ("secure_core", "insecure_variant"):
        report_path = ROOT_DIR / "docs" / f"{variant}_attack_report.json"
        if report_path.exists():
            payload[variant] = json.loads(report_path.read_text(encoding="utf-8"))
    return JSONResponse(payload)


def _open_browser() -> None:
    time.sleep(0.4)
    webbrowser.open(f"http://{APP_HOST}:{APP_PORT}")


def main() -> None:
    threading.Thread(target=_open_browser, daemon=True).start()
    uvicorn.run(app, host=APP_HOST, port=APP_PORT)


if __name__ == "__main__":
    main()
