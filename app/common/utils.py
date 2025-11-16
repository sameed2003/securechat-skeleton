"""
Helper signatures: now_ms, b64e, b64d, sha256_hex.
"""

import time
import base64
import hashlib


def now_ms() -> int:
    """
    Return current time in milliseconds since epoch.
    """
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """
    Encode bytes to a base64 string.
    """
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    """
    Decode a base64 string back to bytes.
    """
    return base64.b64decode(s.encode("ascii"))


def sha256_hex(data: bytes) -> str:
    """
    Return SHA-256 hash of data as a hex string.
    """
    return hashlib.sha256(data).hexdigest()

if __name__ == "__main__":
    s = b"hello world"
    print("B64:", b64e(s))
    print("Decoded:", b64d(b64e(s)))
    print("SHA256:", sha256_hex(s))
    print("Now (ms):", now_ms())
