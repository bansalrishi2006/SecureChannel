from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID


@dataclass
class TrustStore:
    ca_cert_pem: bytes
    revoked_serials: set[int] = field(default_factory=set)


@dataclass
class Identity:
    cert_pem: bytes
    key_pem: bytes


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def generate_ca(common_name: str = "SecureChannel Root CA") -> Identity:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return Identity(
        cert_pem=cert.public_bytes(serialization.Encoding.PEM),
        key_pem=key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def issue_certificate(ca: Identity, common_name: str, days_valid: int = 365) -> Identity:
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem)
    ca_key = serialization.load_pem_private_key(ca.key_pem, None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return Identity(
        cert_pem=cert.public_bytes(serialization.Encoding.PEM),
        key_pem=key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def validate_certificate(
    cert_pem: bytes,
    trust_store: TrustStore,
    *,
    allow_expired: bool = False,
    allow_self_signed: bool = False,
    skip_chain_validation: bool = False,
) -> None:
    cert = x509.load_pem_x509_certificate(cert_pem)
    ca_cert = x509.load_pem_x509_certificate(trust_store.ca_cert_pem)
    now = datetime.now(timezone.utc)
    if cert.serial_number in trust_store.revoked_serials:
        raise ValueError("certificate revoked")
    if not allow_expired and (now < cert.not_valid_before_utc or now > cert.not_valid_after_utc):
        raise ValueError("certificate expired or not yet valid")
    if cert.issuer == cert.subject and not allow_self_signed:
        raise ValueError("self-signed cert not allowed")
    if not skip_chain_validation:
        if cert.issuer != ca_cert.subject:
            raise ValueError("untrusted issuer")
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )


def make_test_pki() -> tuple[Identity, Identity, Identity, TrustStore]:
    ca = generate_ca()
    server = issue_certificate(ca, "secure-server")
    client = issue_certificate(ca, "secure-client")
    trust = TrustStore(ca_cert_pem=ca.cert_pem)
    return ca, server, client, trust


def revoke_certificate(identity: Identity, trust_store: TrustStore) -> None:
    cert = x509.load_pem_x509_certificate(identity.cert_pem)
    trust_store.revoked_serials.add(cert.serial_number)
