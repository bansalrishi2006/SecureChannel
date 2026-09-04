from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pqcrypto.kem import ml_kem_768

PROTOCOL_VERSION = "1.0"
CIPHER_HYBRID = "HYBRID_X25519_MLKEM768_AES256_GCM"
CIPHER_X25519_ONLY = "X25519_ONLY_AES256_GCM"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw()


def x25519_shared(priv: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    peer = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return priv.exchange(peer)


def kyber_keypair() -> tuple[bytes, bytes]:
    public_key, secret_key = ml_kem_768.keygen()
    return bytes(public_key), bytes(secret_key)


def kyber_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    ct, ss = ml_kem_768.encaps(public_key)
    return bytes(ct), bytes(ss)


def kyber_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    return bytes(ml_kem_768.decaps(secret_key, ciphertext))


@dataclass(frozen=True)
class KeySchedule:
    c2s_key: bytes
    s2c_key: bytes
    transcript_key: bytes


def derive_keys(shared_secret: bytes, transcript: bytes) -> KeySchedule:
    salt = hashlib.sha256(transcript).digest()
    material = HKDF(algorithm=hashes.SHA256(), length=96, salt=salt, info=b"SecureChannel-v1").derive(shared_secret)
    return KeySchedule(c2s_key=material[:32], s2c_key=material[32:64], transcript_key=material[64:96])


def transcript_hmac(key: bytes, transcript: bytes, purpose: bytes) -> bytes:
    return hmac.new(key, transcript + b"|" + purpose, hashlib.sha256).digest()


def aesgcm_encrypt(key: bytes, seq: int, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = seq.to_bytes(12, "big")
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aesgcm_decrypt(key: bytes, seq: int, ciphertext: bytes, aad: bytes = b"") -> bytes:
    nonce = seq.to_bytes(12, "big")
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
