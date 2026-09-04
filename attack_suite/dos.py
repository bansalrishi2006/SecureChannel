from __future__ import annotations

import socket
import threading
import time

from secure_core.client import SecureClient
from secure_core.pki import TrustStore

from . import emit_attack_result, emit_attack_start
from .report import AttackResult, AttackTarget


class DoSAttack:
    def run(self, target: AttackTarget) -> AttackResult:
        emit_attack_start("dos", target)
        sockets: list[socket.socket] = []

        def flood() -> None:
            for _ in range(24):
                try:
                    s = socket.create_connection((target.host, target.port), timeout=0.2)
                    sockets.append(s)
                except OSError:
                    break

        start = time.time()
        flood_thread = threading.Thread(target=flood, daemon=True)
        flood_thread.start()
        time.sleep(0.1)
        trust = TrustStore(ca_cert_pem=target.ca_cert_pem)
        client = target.client_cls(target.host, target.port, target.client_identity, trust)
        try:
            client.connect()
            elapsed = time.time() - start
            client.close()
            if elapsed > 2.0:
                return emit_attack_result("dos", target, AttackResult("dos", "succeeded", f"legitimate client delayed to {elapsed:.2f}s"))
            return emit_attack_result("dos", target, AttackResult("dos", "blocked", f"legitimate client connected in {elapsed:.2f}s"))
        except Exception as exc:
            return emit_attack_result("dos", target, AttackResult("dos", "succeeded", f"legitimate client denied: {exc}"))
        finally:
            for s in sockets:
                try:
                    s.close()
                except OSError:
                    pass
            flood_thread.join(timeout=1)
