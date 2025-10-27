#!/usr/bin/env python3
"""
elgamal_ec_benchmark.py

ElGamal-style encryption on secp256r1 (ECDH + HKDF -> AES-GCM).
Measures keygen/encrypt/decrypt timings for various message sizes and saves CSV.
"""

import os
import time
import statistics
import argparse
import csv
from typing import Tuple, List

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.backends import default_backend

# ----------------- Crypto helpers -----------------
def generate_ec_keypair() -> ec.EllipticCurvePrivateKey:
    """Generate a secp256r1 private key."""
    return ec.generate_private_key(ec.SECP256R1(), backend=default_backend())

def serialize_private_key_pem(priv: ec.EllipticCurvePrivateKey, password: bytes = None) -> bytes:
    if password:
        enc_alg = serialization.BestAvailableEncryption(password)
    else:
        enc_alg = serialization.NoEncryption()
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_alg
    )

def serialize_public_key_bytes(pub: ec.EllipticCurvePublicKey) -> bytes:
    """Return X9.62 uncompressed point bytes for the public key."""
    return pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def load_public_key_from_bytes(data: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)

# AES-GCM helpers (AES-256-GCM)
def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = None) -> bytes:
    aesgcm = aead.AESGCM(key)
    iv = os.urandom(12)
    ct = aesgcm.encrypt(iv, plaintext, aad)
    # store: iv || ct
    return iv + ct

def aes_gcm_decrypt(key: bytes, data: bytes, aad: bytes = None) -> bytes:
    aesgcm = aead.AESGCM(key)
    iv = data[:12]
    ct = data[12:]
    return aesgcm.decrypt(iv, ct, aad)

# EC-ElGamal-style hybrid encryption (ephemeral ECDH -> HKDF -> AES-GCM)
def ec_elgamal_encrypt(receiver_pub: ec.EllipticCurvePublicKey, plaintext: bytes) -> bytes:
    # generate ephemeral key
    eph_priv = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    eph_pub = eph_priv.public_key()
    # ECDH shared secret
    shared = eph_priv.exchange(ec.ECDH(), receiver_pub)
    # derive symmetric key (32 bytes / 256 bits)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ec-elgamal",
        backend=default_backend()
    ).derive(shared)
    # encrypt payload
    ciphertext = aes_gcm_encrypt(derived_key, plaintext)
    eph_bytes = serialize_public_key_bytes(eph_pub)
    # package: 2 byte length || eph_bytes || ciphertext
    eph_len = len(eph_bytes).to_bytes(2, "big")
    return eph_len + eph_bytes + ciphertext

def ec_elgamal_decrypt(receiver_priv: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    eph_len = int.from_bytes(data[:2], "big")
    eph_bytes = data[2:2+eph_len]
    ciphertext = data[2+eph_len:]
    eph_pub = load_public_key_from_bytes(eph_bytes)
    shared = receiver_priv.exchange(ec.ECDH(), eph_pub)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ec-elgamal",
        backend=default_backend()
    ).derive(shared)
    plaintext = aes_gcm_decrypt(derived_key, ciphertext)
    return plaintext

# ----------------- Benchmark driver -----------------
def benchmark(message_sizes: List[int], trials: int = 5) -> List[dict]:
    """
    For each message size, generate recipient key (we measure keygen times separately),
    then measure encrypt and decrypt latencies averaged across 'trials'.
    Returns list of dicts (rows).
    """
    rows = []

    # Measure keygen times (separate small benchmark)
    keygen_times = []
    for _ in range(trials):
        t0 = time.perf_counter()
        _ = generate_ec_keypair()
        t1 = time.perf_counter()
        keygen_times.append(t1 - t0)
    keygen_avg = statistics.mean(keygen_times)
    keygen_std = statistics.stdev(keygen_times) if trials > 1 else 0.0

    for size in message_sizes:
        # random payload (simulate patient record bytes)
        payload = os.urandom(size)

        # Create single recipient keypair to use for trials
        recipient_priv = generate_ec_keypair()
        recipient_pub = recipient_priv.public_key()

        enc_times = []
        dec_times = []
        ciphertext_sizes = []

        for _ in range(trials):
            # encryption
            t0 = time.perf_counter()
            ct = ec_elgamal_encrypt(recipient_pub, payload)
            t1 = time.perf_counter()
            # decryption
            t2 = time.perf_counter()
            pt = ec_elgamal_decrypt(recipient_priv, ct)
            t3 = time.perf_counter()

            # verify correctness
            if pt != payload:
                raise RuntimeError("Decrypted plaintext does not match original!")

            enc_times.append(t1 - t0)
            dec_times.append(t3 - t2)
            ciphertext_sizes.append(len(ct))

        rows.append({
            "message_size_bytes": size,
            "trials": trials,
            "ec_keygen_avg_s": keygen_avg,
            "ec_keygen_std_s": keygen_std,
            "encrypt_avg_s": statistics.mean(enc_times),
            "encrypt_std_s": statistics.stdev(enc_times) if trials > 1 else 0.0,
            "decrypt_avg_s": statistics.mean(dec_times),
            "decrypt_std_s": statistics.stdev(dec_times) if trials > 1 else 0.0,
            "ciphertext_size_bytes_avg": int(statistics.mean(ciphertext_sizes))
        })

    return rows

def save_csv(rows: List[dict], filename: str):
    if not rows:
        raise ValueError("No rows to save.")
    fieldnames = list(rows[0].keys())
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

# ----------------- CLI -----------------
def parse_args():
    p = argparse.ArgumentParser(description="EC ElGamal benchmark (secp256r1).")
    p.add_argument("--sizes", nargs="+", type=int, default=[256, 1024, 10*1024],
                   help="Message sizes in bytes (space separated).")
    p.add_argument("--trials", type=int, default=5, help="Number of trials per size.")
    p.add_argument("--out", default="elgamal_ec_timings.csv", help="CSV output filename.")
    return p.parse_args()

def main():
    args = parse_args()
    print(f"Running EC-ElGamal benchmark on secp256r1\nSizes: {args.sizes}\nTrials: {args.trials}\n")
    rows = benchmark(args.sizes, trials=args.trials)
    save_csv(rows, args.out)
    print(f"Saved results to {args.out}\n")
    # print a summary
    for r in rows:
        print(f"size={r['message_size_bytes']} bytes  enc_avg={r['encrypt_avg_s']:.6f}s  dec_avg={r['decrypt_avg_s']:.6f}s  ct_avg={r['ciphertext_size_bytes_avg']} bytes")

if __name__ == "__main__":
    main()
