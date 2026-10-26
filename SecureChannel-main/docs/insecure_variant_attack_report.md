# Attack Report (insecure_variant)

| Attack | Outcome | Details |
|---|---|---|
| mitm | succeeded | client accepted attacker certificate |
| replay | succeeded | server accepted replayed ciphertext |
| downgrade | succeeded | server negotiated X25519-only mode |
| cert_spoof | succeeded | server accepted forged client certificate |
| dos | succeeded | legitimate client denied: [Errno 104] Connection reset by peer |
