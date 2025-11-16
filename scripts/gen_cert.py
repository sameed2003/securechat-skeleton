"""
Generate a certificate signed by the Root CA.
Usage:
  python gen_cert.py --cn server --ca-key certs/ca.key.pem --ca-cert certs/ca.cert.pem --out certs/server
"""

import argparse
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def load_ca(ca_key_path, ca_cert_path):
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    return ca_key, ca_cert


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cn", required=True, help="Common Name of the certificate (e.g., server or client)")
    parser.add_argument("--ca-key", required=True)
    parser.add_argument("--ca-cert", required=True)
    parser.add_argument("--out", required=True, help="Output prefix (e.g., certs/server)")
    args = parser.parse_args()

    ca_key, ca_cert = load_ca(args["ca_key"] if isinstance(args, dict) else args.ca_key,
                              args["ca_cert"] if isinstance(args, dict) else args.ca_cert)

    # Generate leaf RSA key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat User"),
        x509.NameAttribute(NameOID.COMMON_NAME, args.cn),
    ])

    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # Write key
    with open(args.out + ".key.pem", "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Write certificate
    with open(args.out + ".cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated {args.out}.key.pem and {args.out}.cert.pem")


if __name__ == "__main__":
    main()
