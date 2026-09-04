from __future__ import annotations

from attack_suite.cert_spoof import CertSpoofAttack
from attack_suite.dos import DoSAttack
from attack_suite.downgrade import DowngradeAttack
from attack_suite.mitm import MITMAttack
from attack_suite.replay import ReplayAttack
from attack_suite.report import AttackTarget, aggregate_reports
from insecure_variant.client import InsecureClient
from insecure_variant.server import InsecureServer
from secure_core.client import SecureClient
from secure_core.pki import make_test_pki
from secure_core.server import SecureServer


def run_demo() -> None:
    ca, server_id, client_id, trust = make_test_pki()
    secure = SecureServer("127.0.0.1", 0, server_id, trust)
    insecure = InsecureServer("127.0.0.1", 0, server_id, trust)
    secure.start()
    insecure.start()

    attacks = [MITMAttack(), ReplayAttack(), DowngradeAttack(), CertSpoofAttack(), DoSAttack()]
    try:
        print("== Legitimate session ==")
        sc = SecureClient("127.0.0.1", secure.port, client_id, trust)
        sc.connect()
        print("secure_core response:", sc.request(b"hello").decode())
        sc.close()

        ic = InsecureClient("127.0.0.1", insecure.port, client_id, trust)
        ic.connect()
        print("insecure_variant response:", ic.request(b"hello").decode())
        ic.close()

        for variant, port, cls in [
            ("secure_core", secure.port, SecureClient),
            ("insecure_variant", insecure.port, InsecureClient),
        ]:
            print(f"\n== Attacks on {variant} ==")
            target = AttackTarget(variant=variant, host="127.0.0.1", port=port, ca_cert_pem=ca.cert_pem, client_identity=client_id, client_cls=cls)
            results = [a.run(target) for a in attacks]
            for r in results:
                print(f"{r.attack}: {r.outcome} ({r.details})")
            aggregate_reports(variant, results, "./docs")
    finally:
        secure.stop()
        insecure.stop()


if __name__ == "__main__":
    run_demo()
