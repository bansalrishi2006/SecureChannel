from __future__ import annotations

import socket

from .handshake import HandshakePolicy, HandshakeProtocol, recv_frame, send_frame
from .pki import Identity, TrustStore
from .session import Session


class SecureClient:
    def __init__(self, host: str, port: int, identity: Identity, trust: TrustStore, policy: HandshakePolicy | None = None):
        self.host = host
        self.port = port
        self.identity = identity
        self.trust = trust
        self.policy = policy or HandshakePolicy()
        self.sock: socket.socket | None = None
        self.session: Session | None = None

    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=5)
        hs = HandshakeProtocol(self.policy)
        result = hs.client_handshake(self.sock, self.identity, self.trust)
        self.session = Session(tx_key=result.tx_key, rx_key=result.rx_key)

    def close(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_message(self, data: bytes) -> dict:
        if not self.sock or not self.session:
            raise RuntimeError("client not connected")
        msg = self.session.encrypt_message(data)
        send_frame(self.sock, msg)
        return msg

    def receive_message(self) -> bytes:
        if not self.sock or not self.session:
            raise RuntimeError("client not connected")
        msg = recv_frame(self.sock)
        if msg.get("type") == "error":
            raise RuntimeError(msg.get("error", "server error"))
        return self.session.decrypt_message(msg)

    def request(self, data: bytes) -> bytes:
        self.send_message(data)
        return self.receive_message()
