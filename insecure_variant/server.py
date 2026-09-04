from __future__ import annotations

from secure_core.server import SecureServer, ServerConfig
from secure_core.pki import Identity, TrustStore


class InsecureServer(SecureServer):
    """Deliberately vulnerable server:
    - Allows X25519-only downgrade
    - Skips strict certificate validation
    - Disables transcript integrity checks
    - Accepts replayed messages
    - Very weak rate limiting
    """

    def __init__(self, host: str, port: int, identity: Identity, trust: TrustStore):
        super().__init__(
            host,
            port,
            identity,
            trust,
            config=ServerConfig(
                variant="insecure_variant",
                require_kyber=False,
                strict_cert_validation=False,
                enforce_transcript_hmac=False,
                allow_replay=True,
                max_handshakes_per_ip_per_window=10_000,
                rate_limit_window_seconds=1,
                handshake_timeout_seconds=20,
                max_concurrent_connections=8,
            ),
        )
