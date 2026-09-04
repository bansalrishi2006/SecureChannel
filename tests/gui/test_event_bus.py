from __future__ import annotations

import json
import time

from secure_core.events import EventBus, events
from secure_core.client import SecureClient
from secure_core.pki import make_test_pki
from secure_core.server import SecureServer


def test_emit_without_subscribers_does_not_raise():
    bus = EventBus()
    bus.emit("test.event", connection_id="c1", variant="secure_core", value=1)


def test_subscriber_receives_expected_keys():
    bus = EventBus()
    received = []
    unsub = bus.subscribe(received.append)
    bus.emit("test.event", connection_id="c2", variant="secure_core", value=2)
    time.sleep(0.05)
    unsub()
    assert len(received) == 1
    event = received[0]
    assert event["event_type"] == "test.event"
    assert event["connection_id"] == "c2"
    assert event["variant"] == "secure_core"
    assert "timestamp" in event


def test_multiple_subscribers_receive_same_event():
    bus = EventBus()
    left = []
    right = []
    unsub_left = bus.subscribe(left.append)
    unsub_right = bus.subscribe(right.append)
    bus.emit("test.multi", connection_id="shared", variant="secure_core")
    time.sleep(0.05)
    unsub_left()
    unsub_right()
    assert len(left) == 1
    assert len(right) == 1
    assert left[0] == right[0]


def test_no_private_key_material_in_events():
    captured = []
    unsubscribe = events.subscribe(captured.append)
    ca, server_id, client_id, trust = make_test_pki()
    server = SecureServer("127.0.0.1", 0, server_id, trust)
    server.start()
    time.sleep(0.05)
    client = SecureClient("127.0.0.1", server.port, client_id, trust)

    try:
        client.connect()
        assert client.request(b"hello-gui") == b"hello-gui"
    finally:
        client.close()
        server.stop()
        time.sleep(0.1)
        unsubscribe()

    serialized = "\n".join(json.dumps(event, sort_keys=True) for event in captured)
    assert "PRIVATE KEY" not in serialized
    assert ca.key_pem.decode("utf-8") not in serialized
    assert server_id.key_pem.decode("utf-8") not in serialized
    assert client_id.key_pem.decode("utf-8") not in serialized
