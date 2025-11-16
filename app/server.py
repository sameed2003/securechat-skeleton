"""
Server skeleton — plain TCP; no TLS.
Uses DH to derive AES-128 session key and decrypts messages.
"""

import socket
import json
import threading
import secrets
from app.common.protocol import Hello, ServerHello, Login, Msg
from app.common.utils import now_ms, b64e, b64d
from app.crypto.sign import load_public_key, rsa_verify
from app.crypto.aes import aes_decrypt
from app.crypto.dh import dh_generate_keypair, dh_derive_session_key
from app.storage.db import UserDB
from app.storage.transcript import Transcript
import hashlib

# Server configuration
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 12345
TRANSCRIPT_FILE = "transcripts/server.jsonl"


class SecureServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((SERVER_HOST, SERVER_PORT))
        self.sock.listen(5)
        print(f"[+] Server listening on {SERVER_HOST}:{SERVER_PORT}")

        with open("secrets.json") as f:
            secrets = json.load(f)

        self.db = UserDB(user=secrets["dbuser"], password=secrets["dbpass"], host=secrets["dbhost"], database="securechat")


        # self.db = UserDB()  # adjust credentials if needed
        self.transcript = Transcript(TRANSCRIPT_FILE)
        self.clients = {}  # username -> (socket, session_key)

    # -------------------
    # TCP Helpers
    # -------------------
    @staticmethod
    def send_json(sock, obj: dict):
        data = json.dumps(obj).encode()
        sock.sendall(len(data).to_bytes(4, "big") + data)

    @staticmethod
    def recv_json(sock) -> dict:
        raw_len = sock.recv(4)
        if not raw_len:
            raise ConnectionError("Client closed")
        msg_len = int.from_bytes(raw_len, "big")
        data = b""
        while len(data) < msg_len:
            chunk = sock.recv(msg_len - len(data))
            if not chunk:
                raise ConnectionError("Client closed")
            data += chunk
        return json.loads(data)

    # -------------------
    # Client handler
    # -------------------
    def handle_client(self, client_sock, addr):
        username = "unknown"
        try:
            # --- Handshake ---
            hello_msg = self.recv_json(client_sock)
            username = hello_msg.get("username", "unknown")

            # Generate server DH keypair for this client
            server_priv, server_pub = dh_generate_keypair()
            challenge_bytes = secrets.token_bytes(16)
            server_hello = ServerHello(
                server_version="1.0",
                challenge=b64e(challenge_bytes),
                dh_pub=b64e(server_pub.to_bytes((server_pub.bit_length() + 7)//8, "big"))
            )
            self.send_json(client_sock, server_hello.model_dump())

            # --- Login ---
            login_msg = Login(**self.recv_json(client_sock))
            user_record = self.db.get_user(login_msg.username)
            if user_record is None:
                self.send_json(client_sock, {"status": "error", "reason": "unknown user"})
                client_sock.close()
                return

            # Verify challenge signature
            pub_key = load_public_key('certs/client.cert.pem')
            try:
                rsa_verify(pub_key, challenge_bytes, b64d(login_msg.signature))
            except ValueError:
                self.send_json(client_sock, {"status": "error", "reason": "invalid signature"})
                client_sock.close()
                return


            # --- Derive AES session key ---
            client_dh_pub_b64 = login_msg.__dict__.get("dh_pub")
            if client_dh_pub_b64:
                client_pub_bytes = b64d(client_dh_pub_b64)
                client_pub_int = int.from_bytes(client_pub_bytes, "big")
                session_key = dh_derive_session_key(server_priv, client_pub_int)
            else:
                session_key = None
            
            if session_key is None:
                self.send_json(client_sock, {"status": "error", "reason": "no session key"})
                client_sock.close()
                return
            
            # Optional: verify password hash
            decrypted_password = aes_decrypt(session_key, b64d(login_msg.password)).decode()
            # print(decrypted_password)
            if not self.db.verify_user(login_msg.username, decrypted_password):
                self.send_json(client_sock, {"status": "error", "reason": "wrong password"})
                client_sock.close()
                return

            # Login successful
            self.send_json(client_sock, {"status": "ok"})
            print(f"[+] {username} logged in from {addr}")
            self.clients[username] = (client_sock, session_key)

            # --- Message loop ---
            while True:
                msg_json = self.recv_json(client_sock)
                msg = Msg(**msg_json)
                # Decrypt message if session key available
                sock, key = self.clients[msg.sender]
                if key:
                    try:
                        decrypted = aes_decrypt(key, b64d(msg.ciphertext)).decode()
                        print(f"[{msg.sender} -> {msg.recipient}]: {decrypted}")
                    except Exception as e:
                        print(f"[!] Failed to decrypt message from {msg.sender}: {e}")
                        continue
                else:
                    print(f"[{msg.sender} -> {msg.recipient}]: {msg.ciphertext}")

                self.transcript.append(msg_json)

                # Relay to recipient if connected
                recipient_entry = self.clients.get(msg.recipient)
                if recipient_entry:
                    recipient_sock, _ = recipient_entry
                    self.send_json(recipient_sock, msg_json)

        except ConnectionError:
            print(f"[-] Client {addr} disconnected")
        except Exception as e:
            print(f"[!] Error handling client {addr}: {e}")
        finally:
            # Cleanup
            if username in self.clients:
                del self.clients[username]
            client_sock.close()

    # -------------------
    # Run server
    # -------------------
    def run(self):
        while True:
            client_sock, addr = self.sock.accept()
            print(f"[+] Accepted connection from {addr}")
            threading.Thread(target=self.handle_client, args=(client_sock, addr), daemon=True).start()


def main():
    server = SecureServer()
    server.run()


if __name__ == "__main__":
    main()
