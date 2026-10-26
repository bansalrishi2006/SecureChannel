from secure_core import crypto
from secure_core.session import ReplayError, Session


def test_hybrid_key_material_derives_consistently():
    transcript = b"transcript"
    shared = b"a" * 64
    a = crypto.derive_keys(shared, transcript)
    b = crypto.derive_keys(shared, transcript)
    assert a == b
    assert len(a.c2s_key) == 32


def test_replay_protection_blocks_duplicate():
    key = b"k" * 32
    sender = Session(tx_key=key, rx_key=key)
    receiver = Session(tx_key=key, rx_key=key)
    packet = sender.encrypt_message(b"hello")
    assert receiver.decrypt_message(packet) == b"hello"
    try:
        receiver.decrypt_message(packet)
        assert False, "expected replay protection"
    except ReplayError:
        pass
