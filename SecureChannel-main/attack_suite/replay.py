from __future__ import annotations

from secure_core.client import SecureClient
from secure_core.pki import TrustStore

from .report import AttackResult, AttackTarget


class ReplayAttack:
    def run(self, target: AttackTarget) -> AttackResult:
        client: SecureClient = target.client_cls(
            target.host, target.port, target.client_identity, TrustStore(ca_cert_pem=target.ca_cert_pem)
        )
        try:
            client.connect()
            captured = client.send_message(b"replay-me")
            first = client.receive_message()
            if first != b"replay-me":
                return AttackResult("replay", "blocked", "baseline message failed")
            from secure_core.handshake import send_frame

            send_frame(client.sock, captured)
            second = client.receive_message()
            if second == b"replay-me":
                return AttackResult("replay", "succeeded", "server accepted replayed ciphertext")
            return AttackResult("replay", "blocked", "replay response differed")
        except Exception as exc:
            return AttackResult("replay", "blocked", f"replay rejected: {exc}")
        finally:
            client.close()
