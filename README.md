## Link of Repo: https://github.com/sameed2003/securechat-skeleton.git
# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository is the **official code skeleton** for your Assignment #2.  
You will build a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.


## 🧩 Overview

You are provided only with the **project skeleton and file hierarchy**.  
Each file contains docstrings and `TODO` markers describing what to implement.

Your task is to:
- Implement the **application-layer protocol**.
- Integrate cryptographic primitives correctly to satisfy the assignment spec.
- Produce evidence of security properties via Wireshark, replay/tamper tests, and signed session receipts.

## 🏗️ Folder Structure
```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 (use cryptography lib)
│  │  ├─ dh.py               # Classic DH helpers + key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN)
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models (hello/login/msg/receipt)
│  │  └─ utils.py            # Helpers (base64, now_ms, sha256_hex)
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/manual/NOTES.md     # Manual testing + Wireshark evidence checklist
├─ certs/.keep               # Local certs/keys (gitignored)
├─ transcripts/.keep         # Session logs (gitignored)
├─ .env.example              # Sample configuration (no secrets)
├─ .gitignore                # Ignore secrets, binaries, logs, and certs
├─ requirements.txt          # Minimal dependencies
└─ .github/workflows/ci.yml  # Compile-only sanity check (no execution)
```

## ⚙️ Setup Instructions

1. **Fork this repository** to your own GitHub account(using official nu email).  
   All development and commits must be performed in your fork.

2. **Set up environment**:
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env
   ```

3. **Initialize MySQL** (recommended via Docker):
   ```bash
   docker run -d --name securechat-db        -e MYSQL_ROOT_PASSWORD=rootpass        -e MYSQL_DATABASE=securechat        -e MYSQL_USER=scuser        -e MYSQL_PASSWORD=scpass        -p 3306:3306 mysql:8
   ```

# SecureChat — Project README

This README describes how to set up, run, and test the SecureChat skeleton in this repository. It includes explicit notes about per-file test harnesses and how the database is created locally using the included script (no Docker required).

Summary:
- Language: Python 3.10+
- Dependencies: See `requirements.txt` (cryptography, PyMySQL, python-dotenv, pydantic, rich)
- Main entry points: `app/server.py`, `app/client.py`
- Cert tools: `scripts/gen_ca.py`, `scripts/gen_cert.py`

## Repo layout (short)
```
<repo root>
├─ app/
│  ├─ client.py
│  ├─ server.py
│  ├─ common/
│  ├─ crypto/
│  └─ storage/
├─ scripts/
├─ certs/
├─ transcripts/
├─ requirements.txt
└─ secrets.json
```

## 1) Environment (Windows / PowerShell)

Create and activate a virtual environment, then install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

## 2) Secrets / DB credentials

- The repo contains a minimal `secrets.json` at the project root with DB credentials used for local testing. The `app/storage/creaate_db.py` script reads from `app/storage/secrets.json` by default — copy the root `secrets.json` to `app/storage/secrets.json` or edit the script to point to the root file before running it.

Do not commit real credentials.

## 3) Generating certificates (local test CA)

Create a local Root CA and then issue server/client certs:

```powershell
python scripts/gen_ca.py --name "Local Test CA"
python scripts/gen_cert.py --cn server --ca-key certs/ca.key.pem --ca-cert certs/ca.cert.pem --out certs/server
python scripts/gen_cert.py --cn client --ca-key certs/ca.key.pem --ca-cert certs/ca.cert.pem --out certs/client
```

The code expects certs/keys at paths like `certs/client.cert.pem` and `certs/client.key.pem`.

## 4) Initialize the database (local script)

This repository includes a simple script to create the `securechat` database without Docker. The file is `app/storage/creaate_db.py` (note the filename contains a typo in this repo). Run it like this:

```powershell
python app/storage/creaate_db.py
```

Notes:
- The script expects a secrets file at `app/storage/secrets.json`. Copy the repo root `secrets.json` there or adjust the script.
- `app/storage/db.py` implements the `UserDB` helper and also contains a `__main__` test harness to verify user add/verify behavior (run with `python app/storage/db.py`).

Docker MySQL is optional — only if you prefer running a DB inside a container. The local script suffices for straightforward tests.

## 5) Per-file test harnesses (run individual modules)

Many modules include a `if __name__ == "__main__":` test harness so you can run and validate each component independently. Examples:

```powershell
python app/crypto/aes.py
python app/crypto/dh.py
python app/crypto/pki.py
python app/crypto/sign.py
python app/common/protocol.py
python app/common/utils.py
python app/storage/transcript.py
python app/storage/db.py
python app/client.py
python app/server.py
```

These commands exercise the module-level examples and are useful for unit-level sanity checks.

## 6) Run server and client (manual)

Start the server in one terminal:

```powershell
python app/server.py
```

Start a client in another terminal:

```powershell
python app/client.py
```

The client will prompt for username and password and then allow sending encrypted messages to other connected users.

## 7) Smoke test (run several module mains)

Run a group of quick smoke checks in PowerShell:

```powershell
&{ python app/crypto/aes.py; python app/crypto/dh.py; python app/crypto/pki.py; python app/crypto/sign.py; python app/common/protocol.py; python app/common/utils.py; python app/storage/db.py }
```

## 8) Tests / CI

- There is no `pytest` suite included by default. To add unit tests, create a `tests/` folder and run `pytest`.

## 9) Transcripts and evidence

- Runtime transcripts are written to `transcripts/` by `app/storage/transcript.py` (e.g., `transcripts/server.jsonl`). Use these for manual evidence and the assignment checklist in `tests/manual/NOTES.md`.

## 10) Troubleshooting

- If `app/storage/creaate_db.py` fails because it cannot find `app/storage/secrets.json`, copy `secrets.json` into `app/storage/` or edit the script to point to the root `secrets.json`.
- If the server cannot connect to the DB, verify host/credentials in the secrets file and that MySQL is running locally.
- If certificates fail to load, verify the expected files exist in `certs/` and names match those used in code.
