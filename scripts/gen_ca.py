"""
Generate a Root CA (RSA key + self-signed certificate) with CLI options.
Outputs:
  certs/ca.key.pem
  certs/ca.cert.pem
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone
import os
import argparse


def main():
    parser = argparse.ArgumentParser(description="Generate Root CA")
    parser.add_argument("--country", default="PK", help="Country Name (2 letters)")
    parser.add_argument("--org", default="SecureChat CA", help="Organization Name")
    parser.add_argument("--name", default="SecureChat Root CA", help="Common Name")
    parser.add_argument("--days", type=int, default=3650, help="Certificate validity in days")
    args = parser.parse_args()

    os.makedirs("certs", exist_ok=True)

    # Generate 2048-bit RSA CA key
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, args.country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, args.org),
        x509.NameAttribute(NameOID.COMMON_NAME, args.name),
    ])

    now = datetime.now(timezone.utc)

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=args.days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # Write private key
    with open("certs/ca.key.pem", "wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Write certificate
    with open("certs/ca.cert.pem", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print("Generated certs/ca.key.pem and certs/ca.cert.pem")


if __name__ == "__main__":
    main()
