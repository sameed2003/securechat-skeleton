"""
AES-128 (ECB) + PKCS#7 padding helpers.
Uses the `cryptography` library.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


AES_BLOCK_SIZE = 16  # bytes


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts using AES-128 in ECB mode with PKCS#7 padding.

    :param key: 16-byte AES key
    :param plaintext: bytes to encrypt
    :return: ciphertext bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")

    # PKCS#7 padding
    padder = padding.PKCS7(AES_BLOCK_SIZE * 8).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts AES-128 ECB + PKCS#7 padded ciphertext.

    :param key: 16-byte AES key
    :param ciphertext: encrypted bytes
    :return: plaintext bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")

    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad
    unpadder = padding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

if __name__ == "__main__":
    key = b"B" * 16 # 16-byte key
    pt = b"hello world!"

    ct = aes_encrypt(key, pt)
    dec = aes_decrypt(key, ct)

    print("Ciphertext:", ct.hex())
    print("Decrypted:", dec)
