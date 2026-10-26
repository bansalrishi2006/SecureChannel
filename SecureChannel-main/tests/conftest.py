from __future__ import annotations

import time

import pytest

from secure_core.pki import make_test_pki
from secure_core.server import SecureServer
from insecure_variant.server import InsecureServer


@pytest.fixture
def pki_bundle():
    return make_test_pki()


@pytest.fixture
def secure_server(pki_bundle):
    _, server_id, _, trust = pki_bundle
    srv = SecureServer("127.0.0.1", 0, server_id, trust)
    srv.start()
    time.sleep(0.05)
    yield srv
    srv.stop()


@pytest.fixture
def insecure_server(pki_bundle):
    _, server_id, _, trust = pki_bundle
    srv = InsecureServer("127.0.0.1", 0, server_id, trust)
    srv.start()
    time.sleep(0.05)
    yield srv
    srv.stop()
