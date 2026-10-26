from __future__ import annotations

import time

from secure_core.client import SecureClient
from secure_core.pki import make_test_pki
from secure_core.server import SecureServer, ServerConfig


def benchmark_handshake(iterations: int = 10) -> dict:
    ca, server_id, client_id, trust = make_test_pki()
    secure = SecureServer("127.0.0.1", 0, server_id, trust, ServerConfig(require_kyber=True))
    insecure = SecureServer("127.0.0.1", 0, server_id, trust, ServerConfig(require_kyber=False))
    secure.start()
    insecure.start()
    try:
        def run(port: int):
            start = time.perf_counter()
            for _ in range(iterations):
                c = SecureClient("127.0.0.1", port, client_id, trust)
                c.connect()
                c.close()
            return (time.perf_counter() - start) / iterations

        return {
            "hybrid_handshake_avg_s": run(secure.port),
            "x25519_only_handshake_avg_s": run(insecure.port),
        }
    finally:
        secure.stop()
        insecure.stop()


if __name__ == "__main__":
    print(benchmark_handshake())
