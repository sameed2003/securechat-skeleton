"""
RSA SHA-256 sign/verify helpers (PKCS#1 v1.5).
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def load_private_key(path: str, password: bytes | None = None) -> rsa.RSAPrivateKey:
    """
    Load an RSA private key from PEM.
    """
    with open(path, "rb") as f:
        data = f.read()

    return serialization.load_pem_private_key(data, password=password)


def load_public_key(path: str):
    """
    Load an RSA public key from a PEM-encoded certificate or key.
    """
    with open(path, "rb") as f:
        data = f.read()

    try:
        # Try loading as a certificate first
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(data)
        pb_key =  cert.public_key()
        print(pb_key)
        return pb_key
    except Exception:
        # Fallback: load as plain public key
        return serialization.load_pem_public_key(data)


def rsa_sign(priv_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """
    Sign message with RSA PKCS#1 v1.5 + SHA-256.
    """
    return priv_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )


def rsa_verify(pub_key, message: bytes, signature: bytes) -> None:
    """
    Verify RSA PKCS#1 v1.5 + SHA-256 signature.

    Raises ValueError on failure.
    """
    try:
        pub_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception as e:
        raise ValueError(f"Invalid signature: {e}")
