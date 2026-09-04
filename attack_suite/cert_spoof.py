from __future__ import annotations

from secure_core.client import SecureClient
from secure_core.pki import generate_ca, issue_certificate, TrustStore

from . import emit_attack_result, emit_attack_start
from .report import AttackResult, AttackTarget


class CertSpoofAttack:
    def run(self, target: AttackTarget) -> AttackResult:
        emit_attack_start("cert_spoof", target)
        rogue_ca = generate_ca("Rogue CA")
        forged_client = issue_certificate(rogue_ca, "spoofed-client")
        trust = TrustStore(ca_cert_pem=target.ca_cert_pem)
        client = SecureClient(target.host, target.port, forged_client, trust)
        try:
            client.connect()
            msg = client.request(b"spoof")
            if msg == b"spoof":
                return emit_attack_result("cert_spoof", target, AttackResult("cert_spoof", "succeeded", "server accepted forged client certificate"))
            return emit_attack_result("cert_spoof", target, AttackResult("cert_spoof", "blocked", "unexpected response"))
        except Exception as exc:
            return emit_attack_result("cert_spoof", target, AttackResult("cert_spoof", "blocked", f"certificate rejected: {exc}"))
        finally:
            client.close()
