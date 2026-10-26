# Architecture

SecureChannel provides parallel implementations: `secure_core` (hardened) and `insecure_variant` (deliberately weak). Both share framing and session interfaces.

- Hybrid key exchange: X25519 + ML-KEM-768 (Kyber)
- Mutual certificate authentication with local CA trust store
- AES-256-GCM protected application messages with per-session sequence counters
- Multi-client threaded TCP server with per-IP handshake rate limiting
