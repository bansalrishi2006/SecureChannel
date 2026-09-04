from __future__ import annotations

from dataclasses import dataclass

from . import crypto


class ReplayError(Exception):
    pass


@dataclass
class Session:
    tx_key: bytes
    rx_key: bytes
    allow_replay: bool = False
    tx_seq: int = 0
    expected_rx_seq: int = 0

    def encrypt_message(self, plaintext: bytes) -> dict:
        seq = self.tx_seq
        self.tx_seq += 1
        ciphertext = crypto.aesgcm_encrypt(self.tx_key, seq, plaintext, aad=seq.to_bytes(8, "big"))
        return {"type": "data", "seq": seq, "ciphertext": crypto.b64e(ciphertext)}

    def decrypt_message(self, message: dict) -> bytes:
        seq = int(message["seq"])
        if not self.allow_replay:
            if seq != self.expected_rx_seq:
                raise ReplayError(f"unexpected sequence: got {seq}, expected {self.expected_rx_seq}")
            self.expected_rx_seq += 1
        ciphertext = crypto.b64d(message["ciphertext"])
        return crypto.aesgcm_decrypt(self.rx_key, seq, ciphertext, aad=seq.to_bytes(8, "big"))
