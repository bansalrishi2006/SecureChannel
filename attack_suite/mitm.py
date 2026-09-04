from __future__ import annotations

import socket
import threading

from secure_core.handshake import HandshakeError, HandshakePolicy, HandshakeProtocol
from secure_core.pki import TrustStore, generate_ca, issue_certificate

from .report import AttackResult, AttackTarget


class MITMAttack:
    def run(self, target: AttackTarget) -> AttackResult:
        rogue_ca = generate_ca("MITM-CA")
        rogue_server = issue_certificate(rogue_ca, "mitm-server")
        trust = TrustStore(ca_cert_pem=target.ca_cert_pem)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        outcome = {"accepted": False, "error": ""}

        def fake_server():
            conn, _ = listener.accept()
            try:
                hs = HandshakeProtocol(
                    HandshakePolicy(require_kyber=False, strict_cert_validation=False, enforce_transcript_hmac=False)
                )
                hs.server_handshake(conn, rogue_server, TrustStore(ca_cert_pem=rogue_ca.cert_pem))
                outcome["accepted"] = True
            except Exception as exc:
                outcome["error"] = str(exc)
            finally:
                conn.close()
                listener.close()

        t = threading.Thread(target=fake_server, daemon=True)
        t.start()
        try:
            client = target.client_cls("127.0.0.1", port, target.client_identity, trust)
            client.connect()
            client.close()
        except Exception as exc:
            outcome["error"] = str(exc)
        t.join(timeout=2)

        if outcome["accepted"]:
            return AttackResult("mitm", "succeeded", "client accepted attacker certificate")
        return AttackResult("mitm", "blocked", f"client rejected MITM: {outcome['error']}")
