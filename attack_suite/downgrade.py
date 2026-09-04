from __future__ import annotations

import socket

from secure_core import crypto
from secure_core.handshake import HandshakePolicy, HandshakeProtocol
from secure_core.pki import TrustStore

from .report import AttackResult, AttackTarget


class DowngradeAttack:
    def run(self, target: AttackTarget) -> AttackResult:
        trust = TrustStore(ca_cert_pem=target.ca_cert_pem)
        sock = socket.create_connection((target.host, target.port), timeout=5)
        try:
            hs = HandshakeProtocol(
                HandshakePolicy(
                    require_kyber=False,
                    strict_cert_validation=True,
                    enforce_transcript_hmac=True,
                    offered_ciphers=[crypto.CIPHER_X25519_ONLY],
                )
            )
            result = hs.client_handshake(sock, target.client_identity, trust)
            if result.selected_cipher == crypto.CIPHER_X25519_ONLY:
                return AttackResult("downgrade", "succeeded", "server negotiated X25519-only mode")
            return AttackResult("downgrade", "blocked", "server kept hybrid mode")
        except Exception as exc:
            return AttackResult("downgrade", "blocked", f"downgrade rejected: {exc}")
        finally:
            sock.close()
