# Threat Model

Covered adversaries:
- On-path attacker that can intercept, modify, inject, and replay traffic.
- Compromised endpoint attacker with long-term key extraction capability.

Controls in `secure_core`:
- Mutual cert verification and transcript HMAC binding.
- Hybrid key exchange with downgrade rejection.
- Replay protection via strict monotonic per-session sequence counters.
- Basic DoS controls: handshake timeouts + per-IP request limiting.
