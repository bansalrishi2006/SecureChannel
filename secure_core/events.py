from __future__ import annotations

import hashlib
import json
import queue
import threading
from datetime import datetime, timezone
from typing import Callable


EventCallback = Callable[[dict], None]


class EventBus:
    def __init__(self, max_queue_size: int = 10000):
        self._subs: list[EventCallback] = []
        self._lock = threading.Lock()
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=max_queue_size)
        self._worker = threading.Thread(target=self._drain, daemon=True)
        self._worker.start()

    def subscribe(self, callback: EventCallback) -> Callable[[], None]:
        with self._lock:
            self._subs.append(callback)

        def unsubscribe() -> None:
            with self._lock:
                if callback in self._subs:
                    self._subs.remove(callback)

        return unsubscribe

    def emit(self, event_type: str, **data) -> None:
        event = {"timestamp": utc_timestamp(), "event_type": event_type}
        event.update(data)
        if "connection_id" not in event:
            event["connection_id"] = "unknown"
        if "variant" not in event:
            event["variant"] = "secure_core"
        try:
            json.dumps(event)
        except (TypeError, ValueError):
            return
        with self._lock:
            has_subscribers = bool(self._subs)
        if not has_subscribers:
            return
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            return

    def _drain(self) -> None:
        while True:
            event = self._queue.get()
            with self._lock:
                callbacks = list(self._subs)
            for callback in callbacks:
                try:
                    callback(event)
                except Exception:
                    continue


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def key_fingerprint(data: bytes, size: int = 8) -> str:
    return hashlib.sha256(data).hexdigest()[:size]


events = EventBus()
