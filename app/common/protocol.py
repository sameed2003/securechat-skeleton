"""
Pydantic models for SecureChat messages:
hello, server_hello, register, login, dh_client, dh_server, msg, receipt.
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


# -------------------
# HELLO / HANDSHAKE
# -------------------
class Hello(BaseModel):
    username: str
    client_version: str = "1.0"


class ServerHello(BaseModel):
    server_version: str = "1.0"
    challenge: str  # random nonce, base64 string
    dh_pub: str             # server's DH public key, base64 string


# -------------------
# REGISTER / LOGIN
# -------------------
class Register(BaseModel):
    username: str
    password_hash: str  # e.g., SHA256(password+salt)
    public_key: str     # PEM string


class Login(BaseModel):
    username: str
    password_hash: str
    signature: Optional[str] = None  # signature of challenge


# -------------------
# DIFFIE-HELLMAN MESSAGES
# -------------------
class DHClient(BaseModel):
    client_pub: str  # base64-encoded DH public
    nonce: Optional[str] = None


class DHServer(BaseModel):
    server_pub: str  # base64-encoded DH public
    session_id: str


# -------------------
# CHAT / MSG
# -------------------
class Msg(BaseModel):
    sender: str
    recipient: str
    timestamp: int    # milliseconds since epoch
    ciphertext: str   # base64-encoded AES message


class Receipt(BaseModel):
    msg_id: str       # unique message identifier
    timestamp: int    # when the message was received


if __name__ == "__main__":
    h = Hello(username="alice")
    print(h.model_dump_json())

    dh = DHClient(client_pub="AAAABBBB==")
    print(dh.model_dump_json())
