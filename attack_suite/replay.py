from __future__ import annotations

from secure_core.client import SecureClient
from secure_core.pki import TrustStore

from . import emit_attack_result, emit_attack_start
from .report import AttackResult, AttackTarget


class ReplayAttack:
    def run(self, target: AttackTarget) -> AttackResult:
        emit_attack_start("replay", target)
        client: SecureClient = target.client_cls(
            target.host, target.port, target.client_identity, TrustStore(ca_cert_pem=target.ca_cert_pem)
        )
        try:
            client.connect()
            captured = client.send_message(b"replay-me")
            first = client.receive_message()
            if first != b"replay-me":
                return emit_attack_result("replay", target, AttackResult("replay", "blocked", "baseline message failed"))
            from secure_core.handshake import send_frame

            send_frame(client.sock, captured)
            second = client.receive_message()
            if second == b"replay-me":
                return emit_attack_result(
                    "replay", target, AttackResult("replay", "succeeded", "server accepted replayed ciphertext")
                )
            return emit_attack_result("replay", target, AttackResult("replay", "blocked", "replay response differed"))
        except Exception as exc:
            return emit_attack_result("replay", target, AttackResult("replay", "blocked", f"replay rejected: {exc}"))
        finally:
            client.close()
