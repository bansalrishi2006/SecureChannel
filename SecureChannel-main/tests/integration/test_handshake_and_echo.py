import pytest

from secure_core.client import SecureClient
from secure_core.pki import TrustStore


def test_secure_client_server_echo(secure_server, pki_bundle):
    _, _, client_id, trust = pki_bundle
    client = SecureClient("127.0.0.1", secure_server.port, client_id, trust)
    client.connect()
    assert client.request(b"ping") == b"ping"
    client.close()


def test_secure_server_rejects_forged_cert(secure_server, pki_bundle):
    from secure_core.pki import generate_ca, issue_certificate

    rogue = generate_ca("rogue")
    forged = issue_certificate(rogue, "fake-client")
    _, _, _, trust = pki_bundle
    client = SecureClient("127.0.0.1", secure_server.port, forged, trust)
    with pytest.raises(Exception):
        client.connect()
