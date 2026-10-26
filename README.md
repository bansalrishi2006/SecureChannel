# SecureChannel

SecureChannel is a Python 3.11+ secure communication framework with:

- `secure_core/` hardened protocol implementation
- `insecure_variant/` deliberately vulnerable implementation
- `attack_suite/` offensive validation modules

## Quick start

```bash
python -m pip install -e .[dev]
pytest
python demo/run_demo.py
```

## Web demo

Install the optional Flask dependency and start the local web app:

```bash
python -m pip install -e ".[web]"
python -m web.app
```

Open `http://127.0.0.1:5000`. The Compose panel sends your message through the selected secure or deliberately insecure client and shows the server echo. Wire view displays the actual length-prefixed JSON application frame and its encrypted payload. Attacker view runs a MITM attempt against that same session: secure mode should block the rogue certificate, while the insecure mode accepts the rogue handshake and lets the attacker decrypt the captured message.
