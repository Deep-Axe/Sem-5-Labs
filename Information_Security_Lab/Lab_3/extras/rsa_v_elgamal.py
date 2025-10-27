import os
import time
import statistics
import pandas as pd
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.backends import default_backend

# ---------- AES-GCM helper functions ----------
def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = None):
    aesgcm = aead.AESGCM(key)
    iv = os.urandom(12)
    ct = aesgcm.encrypt(iv, plaintext, aad)
    return iv + ct  # prepend IV

def aes_gcm_decrypt(key: bytes, data: bytes, aad: bytes = None):
    aesgcm = aead.AESGCM(key)
    iv, ct = data[:12], data[12:]
    return aesgcm.decrypt(iv, ct, aad)

# ---------- RSA hybrid encryption ----------
def rsa_generate_key(key_size=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())

def rsa_encrypt(public_key, plaintext: bytes):
    sym_key = os.urandom(32)
    ciphertext = aes_gcm_encrypt(sym_key, plaintext)
    enc_key = public_key.encrypt(
        sym_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return len(enc_key).to_bytes(4, "big") + enc_key + ciphertext

def rsa_decrypt(private_key, data: bytes):
    enc_key_len = int.from_bytes(data[:4], "big")
    enc_key = data[4:4+enc_key_len]
    ciphertext = data[4+enc_key_len:]
    sym_key = private_key.decrypt(
        enc_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return aes_gcm_decrypt(sym_key, ciphertext)

# ---------- EC-ElGamal-like hybrid encryption ----------
def ec_generate_key():
    return ec.generate_private_key(ec.SECP256R1(), backend=default_backend())

def ec_public_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def ec_load_public_bytes(data: bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)

def ec_encrypt(receiver_public, plaintext: bytes):
    eph_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared = eph_priv.exchange(ec.ECDH(), receiver_public)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ec-elgamal").derive(shared)
    eph_bytes = ec_public_bytes(eph_priv.public_key())
    ciphertext = aes_gcm_encrypt(derived_key, plaintext)
    return len(eph_bytes).to_bytes(2, "big") + eph_bytes + ciphertext

def ec_decrypt(receiver_priv, data: bytes):
    eph_len = int.from_bytes(data[:2], "big")
    eph_bytes = data[2:2+eph_len]
    ciphertext = data[2+eph_len:]
    eph_pub = ec_load_public_bytes(eph_bytes)
    shared = receiver_priv.exchange(ec.ECDH(), eph_pub)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ec-elgamal").derive(shared)
    return aes_gcm_decrypt(derived_key, ciphertext)

# ---------- Benchmark driver ----------
def measure_algorithms(message_sizes=[1024, 10*1024], trials=5):
    rows = []
    for size in message_sizes:
        msg = os.urandom(size)

        # RSA
        rsa_keygen_times = []
        for _ in range(trials):
            t0 = time.perf_counter()
            rsa_generate_key()
            rsa_keygen_times.append(time.perf_counter() - t0)
        rsa_priv = rsa_generate_key()
        rsa_pub = rsa_priv.public_key()

        rsa_enc_times, rsa_dec_times = [], []
        for _ in range(trials):
            t0 = time.perf_counter()
            ct = rsa_encrypt(rsa_pub, msg)
            t1 = time.perf_counter()
            t2 = time.perf_counter()
            pt = rsa_decrypt(rsa_priv, ct)
            t3 = time.perf_counter()
            assert pt == msg
            rsa_enc_times.append(t1 - t0)
            rsa_dec_times.append(t3 - t2)
        rsa_ct_size = len(ct)

        # ECC
        ec_keygen_times = []
        for _ in range(trials):
            t0 = time.perf_counter()
            ec_generate_key()
            ec_keygen_times.append(time.perf_counter() - t0)
        ec_priv = ec_generate_key()
        ec_pub = ec_priv.public_key()
        ec_enc_times, ec_dec_times = [], []
        for _ in range(trials):
            t0 = time.perf_counter()
            ct = ec_encrypt(ec_pub, msg)
            t1 = time.perf_counter()
            t2 = time.perf_counter()
            pt = ec_decrypt(ec_priv, ct)
            t3 = time.perf_counter()
            assert pt == msg
            ec_enc_times.append(t1 - t0)
            ec_dec_times.append(t3 - t2)
        ec_ct_size = len(ct)

        rows.append({
            "message_size_bytes": size,
            "rsa_keygen_avg_s": statistics.mean(rsa_keygen_times),
            "rsa_encrypt_avg_s": statistics.mean(rsa_enc_times),
            "rsa_decrypt_avg_s": statistics.mean(rsa_dec_times),
            "rsa_ciphertext_size_bytes": rsa_ct_size,
            "ec_keygen_avg_s": statistics.mean(ec_keygen_times),
            "ec_encrypt_avg_s": statistics.mean(ec_enc_times),
            "ec_decrypt_avg_s": statistics.mean(ec_dec_times),
            "ec_ciphertext_size_bytes": ec_ct_size
        })
    return pd.DataFrame(rows)

if __name__ == "__main__":
    df = measure_algorithms([1024, 10*1024], trials=5)
    df.to_csv("encryption_timings.csv", index=False)
    print(df)
    print("\nResults saved to encryption_timings.csv")
