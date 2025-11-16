from sign import load_private_key, load_public_key, rsa_sign, rsa_verify

priv = load_private_key("certs/server.key.pem")
pub = load_public_key("certs/server.cert.pem")

msg = b"hello world"
sig = rsa_sign(priv, msg)

print("Signature:", sig.hex())

# Should not raise
rsa_verify(pub, msg, sig)
print("OK: signature valid")

# Should raise error
try:
    rsa_verify(pub, b"wrong", sig)
except Exception as e:
    print("Expected failure:", e)
