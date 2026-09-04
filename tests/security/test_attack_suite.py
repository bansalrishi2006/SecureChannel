from attack_suite.cert_spoof import CertSpoofAttack
from attack_suite.dos import DoSAttack
from attack_suite.downgrade import DowngradeAttack
from attack_suite.mitm import MITMAttack
from attack_suite.replay import ReplayAttack
from attack_suite.report import AttackTarget
from insecure_variant.client import InsecureClient
from secure_core.client import SecureClient


def _target(variant, host, port, ca_cert, client_identity, client_cls):
    return AttackTarget(
        variant=variant,
        host=host,
        port=port,
        ca_cert_pem=ca_cert,
        client_identity=client_identity,
        client_cls=client_cls,
    )


def test_attacks_blocked_on_secure(secure_server, pki_bundle):
    ca, _, client_id, _ = pki_bundle
    target = _target("secure_core", "127.0.0.1", secure_server.port, ca.cert_pem, client_id, SecureClient)
    results = [
        MITMAttack().run(target),
        ReplayAttack().run(target),
        DowngradeAttack().run(target),
        CertSpoofAttack().run(target),
        DoSAttack().run(target),
    ]
    assert all(r.outcome == "blocked" for r in results)


def test_attacks_succeed_on_insecure(insecure_server, pki_bundle):
    ca, _, client_id, _ = pki_bundle
    target = _target("insecure_variant", "127.0.0.1", insecure_server.port, ca.cert_pem, client_id, InsecureClient)
    results = {
        r.attack: r.outcome
        for r in [
            MITMAttack().run(target),
            ReplayAttack().run(target),
            DowngradeAttack().run(target),
            CertSpoofAttack().run(target),
            DoSAttack().run(target),
        ]
    }
    assert results["mitm"] == "succeeded"
    assert results["replay"] == "succeeded"
    assert results["downgrade"] == "succeeded"
    assert results["cert_spoof"] == "succeeded"
    assert results["dos"] == "succeeded"
