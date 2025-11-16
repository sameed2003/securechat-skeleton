"""
Client skeleton — plain TCP; no TLS.
Uses DH to derive AES-128 session key and encrypts messages.
"""

import socket
import json
from app.common.protocol import Hello, Login, Msg
from app.common.utils import now_ms, b64e, b64d
from app.storage.transcript import Transcript
from app.crypto.sign import load_private_key, rsa_sign
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.dh import dh_generate_keypair, dh_derive_session_key

# Server configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345
TRANSCRIPT_FILE = "transcripts/client.jsonl"


class SecureClient:
    def __init__(self, username: str, key_path: str):
        self.username = username
        self.priv_key = load_private_key(key_path)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.transcript = Transcript(TRANSCRIPT_FILE)
        self.session_key = None  # 16-byte AES key derived from DH
        self.dh_priv = None
        self.dh_pub = None

    # -------------------
    # TCP Helpers
    # -------------------
    def send_json(self, obj: dict):
        data = json.dumps(obj).encode()
        self.sock.sendall(len(data).to_bytes(4, "big") + data)

    def recv_json(self) -> dict:
        raw_len = self.sock.recv(4)
        if not raw_len:
            raise ConnectionError("Server closed")
        msg_len = int.from_bytes(raw_len, "big")
        data = b""
        while len(data) < msg_len:
            chunk = self.sock.recv(msg_len - len(data))
            if not chunk:
                raise ConnectionError("Server closed")
            data += chunk
        return json.loads(data)

    # -------------------
    # Workflow
    # -------------------
    def connect(self):
        self.sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[+] Connected to {SERVER_HOST}:{SERVER_PORT}")

    def handshake(self):
        """Send Hello and receive ServerHello challenge (with server DH pub key)."""
        hello = Hello(username=self.username)
        self.send_json(hello.dict())
        server_hello = self.recv_json()
        print("[*] Server challenge:", server_hello.get("challenge"))
        return server_hello

    def login(self, password: str, challenge: str):
        """Send Login with password hash and signed challenge."""
        import hashlib
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        sig = rsa_sign(self.priv_key, challenge.encode())
        login_msg = Login(
            username=self.username,
            password_hash=password_hash,
            signature=b64e(sig)
        )
        self.send_json(login_msg.dict())
        resp = self.recv_json()
        print("[*] Login response:", resp)
        return resp

    # -------------------
    # DH / AES Session
    # -------------------
    def establish_session_key(self, server_pub_b64: str):
        """Compute DH shared key and truncate to 16 bytes for AES-128."""
        self.dh_priv, self.dh_pub = dh_generate_keypair()
        server_pub_bytes = b64d(server_pub_b64)
        self.session_key = dh_derive_session_key(self.dh_priv, int.from_bytes(server_pub_bytes, "big"))
        return self.dh_pub

    # -------------------
    # Encrypted messaging
    # -------------------
    def send_message(self, recipient: str, text: str):
        if self.session_key is None:
            raise ValueError("Session key not established")
        ct_bytes = aes_encrypt(self.session_key, text.encode())
        msg = Msg(
            sender=self.username,
            recipient=recipient,
            timestamp=now_ms(),
            ciphertext=b64e(ct_bytes)
        )
        self.send_json(msg.dict())
        self.transcript.append(msg.dict())
        print(f"[+] Sent encrypted message to {recipient}")

    def receive_message(self, msg_json: dict):
        ct_bytes = b64d(msg_json["ciphertext"])
        pt = aes_decrypt(self.session_key, ct_bytes)
        print(f"[{msg_json['sender']} -> {msg_json['recipient']}]: {pt.decode()}")
        self.transcript.append(msg_json)

    def close(self):
        self.sock.close()


def main():
    username = input("Username: ")
    password = input("Password: ")
    key_path = f"certs/{username}.key.pem"

    client = SecureClient(username, key_path)
    client.connect()
    server_hello = client.handshake()
    client.login(password, server_hello.get("challenge"))

    # Example DH session establishment (server_pub should come from ServerHello)
    server_pub_b64 = server_hello.get("challenge")
    client_pub = client.establish_session_key(server_pub_b64)
    print(f"[*] Session key established. Client DH pub key: {b64e(client_pub.to_bytes((client_pub.bit_length() + 7)//8, 'big'))}")

    try:
        while True:
            recipient = input("Recipient: ")
            text = input("Message: ")
            if text.lower() in ("quit", "exit"):
                break
            client.send_message(recipient, text)
    finally:
        client.close()


if __name__ == "__main__":
    main()
