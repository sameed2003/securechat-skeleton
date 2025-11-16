"""
Classic Diffie–Hellman helpers + Trunc16(SHA256(Ks)) derivation.
"""

import secrets
import hashlib


# You must use a known safe prime. This one is 2048-bit MODP Group from RFC 3526.
# (Same group used in many DH examples)
# Group 14: 2048-bit prime
MODP_2048_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF",
    16
)

MODP_2048_G = 2  # generator


def dh_generate_keypair():
    """
    Generates a DH keypair.

    Returns:
        (priv, pub) where:
          - priv is a random 256-bit integer
          - pub = g^priv mod p
    """
    # 256-bit random private exponent (safe enough for DH)
    priv = secrets.randbits(256)
    pub = pow(MODP_2048_G, priv, MODP_2048_P)
    return priv, pub


def dh_compute_shared(priv, peer_pub):
    """
    Computes classic DH shared secret:
        Ks = peer_pub^priv mod p

    Returns:
        raw shared secret bytes (big-endian)
    """
    if not (0 < peer_pub < MODP_2048_P):
        raise ValueError("Invalid DH peer public value")

    Ks = pow(peer_pub, priv, MODP_2048_P)

    # Convert integer to big-endian bytes
    # Pad to full size so SHA256 is stable
    length = (MODP_2048_P.bit_length() + 7) // 8
    return Ks.to_bytes(length, "big")


def derive_key_trunc16(shared_secret_bytes):
    """
    Computes SHA256(Ks) and returns the first 16 bytes.
    (Required by assignment)

    Returns:
        16-byte AES key
    """
    h = hashlib.sha256(shared_secret_bytes).digest()
    return h[:16]


# Convenience one-shot API
def dh_derive_session_key(priv, peer_pub):
    """
    Convenience helper:
        1. Compute DH shared secret
        2. Hash with SHA256
        3. Return first 16 bytes (AES key)
    """
    Ks_bytes = dh_compute_shared(priv, peer_pub)
    return derive_key_trunc16(Ks_bytes)

if __name__ == "__main__":
    # Alice
    a_priv, a_pub = dh_generate_keypair()

    # Bob
    b_priv, b_pub = dh_generate_keypair()

    # Both sides derive session key
    key1 = dh_derive_session_key(a_priv, b_pub)
    key2 = dh_derive_session_key(b_priv, a_pub)

    print("Match:", key1 == key2)
    print("Session key:", key1.hex())
