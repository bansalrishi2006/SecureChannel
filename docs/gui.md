# SecureChannel GUI

## What it shows

The GUI is a local observability screen for SecureChannel runtime behavior:

- Handshake message flow (client/server sequence)
- Key-derivation fingerprints (hashed/truncated only)
- Per-event live protocol/session/attack logs
- Attack controls and live `AttackResult` outcomes for `secure_core` vs `insecure_variant`
- Last saved attack reports from `docs/*_attack_report.json`

## Launch

```bash
securechannel-gui
```

or

```bash
python -m gui.server
```

Then open `http://127.0.0.1:8765` if a browser tab is not opened automatically.

## Security note

This GUI is strictly an observability/demo layer. It subscribes to emitted events and does not participate in, gate, or alter protocol cryptography, handshake, session validation, or security guarantees.
