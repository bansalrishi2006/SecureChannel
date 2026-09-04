from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass

from . import crypto
from .pki import Identity, TrustStore, validate_certificate


class HandshakeError(Exception):
    pass


def _canon(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def send_frame(sock: socket.socket, payload: dict) -> None:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack("!I", len(encoded)) + encoded)


def recv_frame(sock: socket.socket, max_size: int = 65536) -> dict:
    header = _recv_exact(sock, 4)
    if not header:
        raise HandshakeError("connection closed")
    (size,) = struct.unpack("!I", header)
    if size <= 0 or size > max_size:
        raise HandshakeError("invalid frame size")
    data = _recv_exact(sock, size)
    try:
        payload = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HandshakeError("invalid json") from exc
    if not isinstance(payload, dict):
        raise HandshakeError("invalid frame")
    return payload


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf.extend(chunk)
    return bytes(buf)


@dataclass
class HandshakePolicy:
    require_kyber: bool = True
    strict_cert_validation: bool = True
    enforce_transcript_hmac: bool = True
    offered_ciphers: list[str] | None = None


@dataclass
class HandshakeResult:
    tx_key: bytes
    rx_key: bytes
    selected_cipher: str


class HandshakeProtocol:
    def __init__(self, policy: HandshakePolicy):
        self.policy = policy

    def client_handshake(self, sock: socket.socket, client_identity: Identity, trust: TrustStore) -> HandshakeResult:
        x_priv, x_pub = crypto.x25519_keypair()
        k_pub, k_sec = crypto.kyber_keypair()

        offered = self.policy.offered_ciphers
        if offered is None:
            offered = [crypto.CIPHER_HYBRID, crypto.CIPHER_X25519_ONLY]
            if self.policy.require_kyber:
                offered = [crypto.CIPHER_HYBRID]

        hello = {
            "type": "client_hello",
            "version": crypto.PROTOCOL_VERSION,
            "offered_ciphers": offered,
            "x25519_pub": crypto.b64e(x_pub),
            "kyber_pub": crypto.b64e(k_pub),
            "client_cert": client_identity.cert_pem.decode("utf-8"),
        }
        send_frame(sock, hello)

        server_hello = recv_frame(sock)
        if server_hello.get("type") != "server_hello":
            raise HandshakeError("expected server_hello")

        selected_cipher = server_hello.get("selected_cipher")
        if self.policy.require_kyber and selected_cipher != crypto.CIPHER_HYBRID:
            raise HandshakeError("downgrade detected")

        validate_certificate(
            server_hello["server_cert"].encode("utf-8"),
            trust,
            allow_expired=not self.policy.strict_cert_validation,
            allow_self_signed=not self.policy.strict_cert_validation,
            skip_chain_validation=not self.policy.strict_cert_validation,
        )

        ecdh = crypto.x25519_shared(x_priv, crypto.b64d(server_hello["x25519_pub"]))
        kyber_shared = b""
        if selected_cipher == crypto.CIPHER_HYBRID:
            kyber_shared = crypto.kyber_decapsulate(k_sec, crypto.b64d(server_hello["kyber_ct"]))

        transcript_server = {
            "type": "server_hello",
            "selected_cipher": selected_cipher,
            "x25519_pub": server_hello["x25519_pub"],
            "kyber_ct": server_hello.get("kyber_ct", ""),
            "server_cert": server_hello["server_cert"],
        }
        transcript = _canon(hello) + _canon(transcript_server)
        schedule = crypto.derive_keys(ecdh + kyber_shared, transcript)

        provided_mac = crypto.b64d(server_hello.get("transcript_hmac", ""))
        expected_mac = crypto.transcript_hmac(schedule.transcript_key, transcript, b"server-hello")
        if self.policy.enforce_transcript_hmac and provided_mac != expected_mac:
            raise HandshakeError("transcript MAC mismatch")

        finished = {
            "type": "finished",
            "verify": crypto.b64e(crypto.transcript_hmac(schedule.transcript_key, transcript, b"client-finished")),
        }
        send_frame(sock, finished)
        done = recv_frame(sock)
        if done.get("type") != "handshake_complete":
            raise HandshakeError("missing completion")
        return HandshakeResult(tx_key=schedule.c2s_key, rx_key=schedule.s2c_key, selected_cipher=selected_cipher)

    def server_handshake(self, sock: socket.socket, server_identity: Identity, trust: TrustStore) -> HandshakeResult:
        hello = recv_frame(sock)
        if hello.get("type") != "client_hello":
            raise HandshakeError("expected client_hello")
        if hello.get("version") != crypto.PROTOCOL_VERSION:
            raise HandshakeError("protocol mismatch")

        offered = hello.get("offered_ciphers") or []
        if crypto.CIPHER_HYBRID in offered:
            selected = crypto.CIPHER_HYBRID
        elif crypto.CIPHER_X25519_ONLY in offered and not self.policy.require_kyber:
            selected = crypto.CIPHER_X25519_ONLY
        else:
            raise HandshakeError("no acceptable cipher")

        validate_certificate(
            hello["client_cert"].encode("utf-8"),
            trust,
            allow_expired=not self.policy.strict_cert_validation,
            allow_self_signed=not self.policy.strict_cert_validation,
            skip_chain_validation=not self.policy.strict_cert_validation,
        )

        x_priv, x_pub = crypto.x25519_keypair()
        ecdh = crypto.x25519_shared(x_priv, crypto.b64d(hello["x25519_pub"]))
        kyber_shared = b""
        kyber_ct = ""

        if selected == crypto.CIPHER_HYBRID:
            kyber_ct_b, kyber_shared = crypto.kyber_encapsulate(crypto.b64d(hello["kyber_pub"]))
            kyber_ct = crypto.b64e(kyber_ct_b)

        server_hello_core = {
            "type": "server_hello",
            "selected_cipher": selected,
            "x25519_pub": crypto.b64e(x_pub),
            "kyber_ct": kyber_ct,
            "server_cert": server_identity.cert_pem.decode("utf-8"),
        }
        transcript = _canon(hello) + _canon(server_hello_core)
        schedule = crypto.derive_keys(ecdh + kyber_shared, transcript)

        server_hello = dict(server_hello_core)
        server_hello["transcript_hmac"] = crypto.b64e(
            crypto.transcript_hmac(schedule.transcript_key, transcript, b"server-hello")
        )
        send_frame(sock, server_hello)

        finished = recv_frame(sock)
        expected = crypto.transcript_hmac(schedule.transcript_key, transcript, b"client-finished")
        if self.policy.enforce_transcript_hmac and crypto.b64d(finished.get("verify", "")) != expected:
            raise HandshakeError("invalid finished")

        send_frame(sock, {"type": "handshake_complete"})
        return HandshakeResult(tx_key=schedule.s2c_key, rx_key=schedule.c2s_key, selected_cipher=selected)
