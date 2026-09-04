from __future__ import annotations

from secure_core.client import SecureClient
from secure_core.handshake import HandshakePolicy
from secure_core.pki import Identity, TrustStore


class InsecureClient(SecureClient):
    """Deliberately vulnerable client: accepts weak/forged server identity and downgrade."""

    def __init__(self, host: str, port: int, identity: Identity, trust: TrustStore):
        super().__init__(
            host,
            port,
            identity,
            trust,
            policy=HandshakePolicy(require_kyber=False, strict_cert_validation=False, enforce_transcript_hmac=False),
        )
        self.variant = "insecure_variant"
