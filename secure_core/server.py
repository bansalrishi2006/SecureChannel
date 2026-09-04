from __future__ import annotations

import socket
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from .events import events
from .handshake import HandshakeError, HandshakePolicy, HandshakeProtocol, recv_frame, send_frame
from .pki import Identity, TrustStore
from .session import ReplayError, Session


@dataclass
class ServerConfig:
    variant: str = "secure_core"
    require_kyber: bool = True
    strict_cert_validation: bool = True
    enforce_transcript_hmac: bool = True
    allow_replay: bool = False
    max_handshakes_per_ip_per_window: int = 200
    rate_limit_window_seconds: int = 10
    handshake_timeout_seconds: int = 4
    max_concurrent_connections: int = 64


class SecureServer:
    def __init__(self, host: str, port: int, identity: Identity, trust: TrustStore, config: ServerConfig | None = None):
        self.host = host
        self.port = port
        self.identity = identity
        self.trust = trust
        self.config = config or ServerConfig()
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._ip_events: dict[str, deque[float]] = defaultdict(deque)
        self._worker_semaphore = threading.BoundedSemaphore(self.config.max_concurrent_connections)

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(100)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()
        if self._thread:
            self._thread.join(timeout=2)

    def _rate_limited(self, ip: str) -> bool:
        now = time.time()
        events = self._ip_events[ip]
        while events and (now - events[0]) > self.config.rate_limit_window_seconds:
            events.popleft()
        if len(events) >= self.config.max_handshakes_per_ip_per_window:
            return True
        events.append(now)
        return False

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except OSError:
                break
            ip, _ = addr
            connection_id = f"{ip}:{addr[1]}-{time.time_ns()}"
            if self._rate_limited(ip):
                events.emit(
                    "server.connection_rate_limited",
                    connection_id=connection_id,
                    variant=self.config.variant,
                    client_ip=ip,
                )
                conn.close()
                continue
            if not self._worker_semaphore.acquire(blocking=False):
                events.emit(
                    "server.connection_concurrency_rejected",
                    connection_id=connection_id,
                    variant=self.config.variant,
                    client_ip=ip,
                )
                conn.close()
                continue
            events.emit(
                "server.connection_accepted",
                connection_id=connection_id,
                variant=self.config.variant,
                client_ip=ip,
            )
            threading.Thread(target=self._handle_client, args=(conn, connection_id), daemon=True).start()

    def _handle_client(self, conn: socket.socket, connection_id: str) -> None:
        conn.settimeout(self.config.handshake_timeout_seconds)
        try:
            hs = HandshakeProtocol(
                HandshakePolicy(
                    require_kyber=self.config.require_kyber,
                    strict_cert_validation=self.config.strict_cert_validation,
                    enforce_transcript_hmac=self.config.enforce_transcript_hmac,
                )
            )
            result = hs.server_handshake(
                conn,
                self.identity,
                self.trust,
                connection_id=connection_id,
                variant=self.config.variant,
            )
            conn.settimeout(10)
            session = Session(
                tx_key=result.tx_key,
                rx_key=result.rx_key,
                allow_replay=self.config.allow_replay,
                connection_id=connection_id,
                variant=self.config.variant,
            )
            while True:
                msg = recv_frame(conn)
                if msg.get("type") != "data":
                    send_frame(conn, {"type": "error", "error": "unexpected message"})
                    break
                try:
                    plaintext = session.decrypt_message(msg)
                except ReplayError:
                    send_frame(conn, {"type": "error", "error": "replay-detected"})
                    if not self.config.allow_replay:
                        break
                    continue
                response = session.encrypt_message(plaintext)
                send_frame(conn, response)
        except (HandshakeError, ValueError, KeyError, OSError) as exc:
            events.emit(
                "server.handshake_failed",
                connection_id=connection_id,
                variant=self.config.variant,
                error=str(exc),
            )
        finally:
            conn.close()
            self._worker_semaphore.release()
            events.emit(
                "server.connection_closed",
                connection_id=connection_id,
                variant=self.config.variant,
            )
