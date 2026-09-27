# SecureChannel

SecureChannel is a Python secure communication framework with:

- `secure_core/` hardened protocol implementation
- `insecure_variant/` deliberately vulnerable implementation
- `attack_suite/` offensive validation modules

## Quick start

```bash
python -m pip install -e .[dev]
pytest
python demo/run_demo.py
```

## Live GUI

The local GUI provides a live sequence diagram, event log, key-fingerprint view, and secure vs. insecure attack outcomes while the demo/attacks run.

```bash
python -m pip install -e ".[dev]"
securechannel-gui
```
