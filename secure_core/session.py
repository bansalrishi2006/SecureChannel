from __future__ import annotations

from dataclasses import dataclass

from . import crypto
from .events import events


class ReplayError(Exception):
    pass


@dataclass
class Session:
    tx_key: bytes
    rx_key: bytes
    allow_replay: bool = False
    connection_id: str = "unknown"
    variant: str = "secure_core"
    tx_seq: int = 0
    expected_rx_seq: int = 0

    def encrypt_message(self, plaintext: bytes) -> dict:
        seq = self.tx_seq
        self.tx_seq += 1
        ciphertext = crypto.aesgcm_encrypt(self.tx_key, seq, plaintext, aad=seq.to_bytes(8, "big"))
        payload = {"type": "data", "seq": seq, "ciphertext": crypto.b64e(ciphertext)}
        events.emit(
            "session.encrypt_message",
            connection_id=self.connection_id,
            variant=self.variant,
            sequence=seq,
            byte_length=len(plaintext),
            outcome="ok",
        )
        return payload

    def decrypt_message(self, message: dict) -> bytes:
        seq = int(message["seq"])
        if not self.allow_replay:
            if seq != self.expected_rx_seq:
                events.emit(
                    "session.replay_detected",
                    connection_id=self.connection_id,
                    variant=self.variant,
                    sequence=seq,
                    expected_sequence=self.expected_rx_seq,
                    outcome="error",
                )
                raise ReplayError(f"unexpected sequence: got {seq}, expected {self.expected_rx_seq}")
            self.expected_rx_seq += 1
        ciphertext = crypto.b64d(message["ciphertext"])
        plaintext = crypto.aesgcm_decrypt(self.rx_key, seq, ciphertext, aad=seq.to_bytes(8, "big"))
        events.emit(
            "session.decrypt_message",
            connection_id=self.connection_id,
            variant=self.variant,
            sequence=seq,
            byte_length=len(plaintext),
            outcome="ok",
        )
        return plaintext
