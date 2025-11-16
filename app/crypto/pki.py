"""
X.509 certificate validation (CA signature, CN match, validity window).
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timezone


def load_certificate(path: str) -> x509.Certificate:
    """
    Load an X.509 certificate from a PEM file.
    """
    with open(path, "rb") as f:
        data = f.read()
    return x509.load_pem_x509_certificate(data)


def load_private_key(path: str, password: bytes | None = None):
    """
    Load a private RSA key (for signing in other modules).
    Not used directly for validation but commonly needed.
    """
    with open(path, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=password)


def verify_certificate_signature(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    """
    Verify that `cert` was signed by `ca_cert`.

    Raises ValueError if verification fails.
    """
    try:
        ca_pub = ca_cert.public_key()

        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        raise ValueError(f"Invalid certificate signature: {e}")


def check_certificate_validity(cert: x509.Certificate) -> None:
    """
    Check if certificate is currently valid (notBefore <= now <= notAfter).

    Raises ValueError if expired or not yet valid.
    """
    now = datetime.now(timezone.utc)

    if now < cert.not_valid_before_utc:
        raise ValueError("Certificate not valid yet")

    if now > cert.not_valid_after_utc:
        raise ValueError("Certificate expired")


def check_certificate_cn(cert: x509.Certificate, expected_cn: str) -> None:
    """
    Verify that the certificate's Common Name (CN) matches `expected_cn`.

    Raises ValueError if CN mismatch.
    """
    try:
        subject = cert.subject
        cn_attr = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0]
        cn = cn_attr.value
    except Exception:
        raise ValueError("Certificate has no CN field")

    if cn != expected_cn:
        raise ValueError(f"CN mismatch: expected '{expected_cn}', got '{cn}'")


def verify_pki_chain(cert: x509.Certificate, ca_cert: x509.Certificate, expected_cn: str) -> None:
    """
    Full validation helper used by client/server before accepting peer cert.

    Steps:
      1. Check CA signature (single-level chain)
      2. Check CN matches expected (client/server name)
      3. Check validity window

    Raises ValueError on any failure.
    """
    verify_certificate_signature(cert, ca_cert)
    check_certificate_cn(cert, expected_cn)
    check_certificate_validity(cert)

if __name__ == "__main__":
    cert = load_certificate("certs/server.cert.pem")
    ca = load_certificate("certs/ca.cert.pem")

    try:
        verify_pki_chain(cert, ca, expected_cn="server")
        print("Certificate OK")
    except Exception as e:
        print("Validation failed:", e)
