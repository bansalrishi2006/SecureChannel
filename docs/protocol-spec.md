# Protocol Specification

Handshake frames (length-prefixed JSON):
1. `client_hello`: version, offered ciphers, X25519 pubkey, ML-KEM pubkey, client cert.
2. `server_hello`: selected cipher, X25519 pubkey, ML-KEM ciphertext (hybrid mode), server cert, transcript HMAC.
3. `finished`: client transcript MAC.
4. `handshake_complete`.

Data frame:
- `data`: sequence number + AES-GCM ciphertext with sequence bound as AAD.

`secure_core` requires hybrid mode and strict certificate/transcript validation. `insecure_variant` intentionally disables these protections.
