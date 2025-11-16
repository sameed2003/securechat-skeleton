"""
Append-only transcript + TranscriptHash helpers.
Each entry is stored as JSON with a rolling hash to ensure integrity.
"""

import os
import json
import hashlib
from typing import Optional, Any
from app.common.utils import sha256_hex, now_ms


class Transcript:
    def __init__(self, path: str):
        """
        Initialize transcript file path.
        If file doesn't exist, create an empty one.
        """
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(self.path):
            with open(self.path, "w") as f:
                f.write("")  # empty file

    def _last_hash(self) -> str:
        """
        Return the last transcript hash (empty string if no entries).
        """
        last_hash = ""
        try:
            with open(self.path, "rb") as f:
                for line in f:
                    if line.strip():
                        entry = json.loads(line)
                        last_hash = entry["hash"]
        except FileNotFoundError:
            pass
        return last_hash

    def append(self, record: dict[str, Any]) -> str:
        """
        Append a record to the transcript.
        Computes rolling hash and returns it.
        Adds timestamp automatically if not present.
        """
        if "timestamp" not in record:
            record["timestamp"] = now_ms()

        prev_hash = self._last_hash()
        record_json = json.dumps(record, sort_keys=True)
        # hash of previous hash + current record
        combined = prev_hash.encode() + record_json.encode()
        new_hash = sha256_hex(combined)

        # store record + hash
        entry = record.copy()
        entry["hash"] = new_hash
        with open(self.path, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

        return new_hash

    def verify(self) -> bool:
        """
        Verify the integrity of the transcript.
        Returns True if all hashes are valid, False otherwise.
        """
        prev_hash = ""
        try:
            with open(self.path, "r") as f:
                for line in f:
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    record = entry.copy()
                    entry_hash = record.pop("hash", None)
                    record_json = json.dumps(record, sort_keys=True)
                    expected_hash = sha256_hex(prev_hash.encode() + record_json.encode())
                    if expected_hash != entry_hash:
                        return False
                    prev_hash = entry_hash
        except FileNotFoundError:
            return True
        return True

if __name__ == "__main__":
    t = Transcript("transcripts/test.jsonl")

    h1 = t.append({"sender": "alice", "recipient": "bob", "message": "Hello"})
    h2 = t.append({"sender": "bob", "recipient": "alice", "message": "Hi"})

    print("Hashes:", h1, h2)
    print("Verify:", t.verify())
