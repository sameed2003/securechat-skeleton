"""
MySQL users table + salted SHA-256 password hashing.
"""

import mysql.connector
from mysql.connector import errorcode
import os
import hashlib
import secrets


class UserDB:
    def __init__(self, host="localhost", user="root", password="", database="securechat"):
        self.conn = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )
        self._create_table()

    def _create_table(self):
        """
        Create users table if it doesn't exist.
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(64) PRIMARY KEY,
                salt CHAR(32) NOT NULL,
                password_hash CHAR(64) NOT NULL,
                public_key TEXT NOT NULL
            )
        """)
        self.conn.commit()
        cursor.close()

    # ---------------------
    # USER HELPERS
    # ---------------------
    def add_user(self, username: str, password: str, public_key: str) -> bool:
        """
        Add a new user with salted SHA-256 password.
        Returns True if success, False if username exists.
        """
        if self.get_user(username) is not None:
            return False

        salt = secrets.token_hex(16)  # 16 bytes -> 32 hex chars
        pwd_hash = self._hash_password(password, salt)

        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, salt, password_hash, public_key) VALUES (%s, %s, %s, %s)",
            (username, salt, pwd_hash, public_key)
        )
        self.conn.commit()
        cursor.close()
        return True

    def verify_user(self, username: str, password: str) -> bool:
        """
        Verify username + password combination.
        """
        user = self.get_user(username)
        if user is None:
            return False

        salt, stored_hash = user["salt"], user["password_hash"]
        return self._hash_password(password, salt) == stored_hash

    def get_user(self, username: str) -> dict | None:
        """
        Fetch user record by username.
        Returns dict with keys: username, salt, password_hash, public_key
        """
        cursor = self.conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        row = cursor.fetchone()
        cursor.close()
        return row

    # ---------------------
    # INTERNAL HELPERS
    # ---------------------
    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        """
        Compute SHA-256 hash of (password + salt) as hex string.
        """
        return hashlib.sha256((password + salt).encode("utf-8")).hexdigest()

if __name__ == "__main__":
    db = UserDB(user="root", password="1234", database="securechat")

    # only un comment to add a new user
    # added = db.add_user("alice", "password123", "PEM_STRING")
    # print("Added:", added)

    verified = db.verify_user("alice", "password123")
    print("Verified:", verified)

    wrong = db.verify_user("alice", "wrongpass")
    print("Wrong password:", not wrong)
