# Attack Report (secure_core)

| Attack | Outcome | Details |
|---|---|---|
| mitm | blocked | client rejected MITM: untrusted issuer |
| replay | blocked | replay rejected: replay-detected |
| downgrade | blocked | downgrade rejected: connection closed |
| cert_spoof | blocked | certificate rejected: connection closed |
| dos | blocked | legitimate client connected in 0.10s |
