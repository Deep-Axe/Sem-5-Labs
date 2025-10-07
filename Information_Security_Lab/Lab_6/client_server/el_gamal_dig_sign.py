#!/usr/bin/env python3
import socket
import hashlib
import random
from math import gcd

def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits=256):
    """Generate a random prime number"""
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1
        if is_prime(num):
            return num


def mod_inverse(a, m):
    """Extended Euclidean Algorithm"""
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m


def generate_elgamal_keys(bits=256):
    """Generate ElGamal keys"""
    print("Generating ElGamal keys...")
    p = generate_prime(bits)
    g = random.randint(2, p - 2)
    x = random.randint(2, p - 2)  # Private key
    y = pow(g, x, p)  # Public key
    return (p, g, y), (p, g, x)


def hash_message(message):
    """Create SHA-256 hash of message"""
    hash_hex = hashlib.sha256(message.encode()).hexdigest()
    return int(hash_hex, 16)


def sign_message(message, private_key):
    """Sign message using ElGamal"""
    p, g, x = private_key
    message_hash = hash_message(message)

    while True:
        k = random.randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            break

    r = pow(g, k, p)
    k_inv = mod_inverse(k, p - 1)
    s = (k_inv * (message_hash - x * r)) % (p - 1)

    return (r, s)


def verify_signature(message, signature, public_key):
    """Verify ElGamal signature"""
    p, g, y = public_key
    r, s = signature

    if not (0 < r < p):
        return False

    message_hash = hash_message(message)

    v1 = pow(y, r, p) * pow(r, s, p) % p
    v2 = pow(g, message_hash, p)

    return v1 == v2


def run_server(host='127.0.0.1', port=5002):

    print("ELGAMAL DIGITAL SIGNATURE SERVER")


    public_key, private_key = generate_elgamal_keys()
    p, g, y = public_key
    print(f"\n[SERVER] Public Key:")
    print(f"  p = {p}")
    print(f"  g = {g}")
    print(f"  y = {y}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f"\n[SERVER] Listening on {host}:{port}...")

    conn, addr = server_socket.accept()
    print(f"\n[SERVER] Connected by {addr}")

    # Send public key
    conn.sendall(f"{p},{g},{y}".encode())

    # Receive client's public key
    client_key_data = conn.recv(4096).decode()
    client_p, client_g, client_y = map(int, client_key_data.split(','))
    client_public_key = (client_p, client_g, client_y)
    print(f"\n[SERVER] Received Client Public Key:")
    print(f"  p = {client_p}")
    print(f"  g = {client_g}")
    print(f"  y = {client_y}")

    # Sign and send message
    server_message = input("\n[SERVER] Enter message to sign and send: ")
    r, s = sign_message(server_message, private_key)
    print(f"[SERVER] Signature (r, s): ({r}, {s})")

    conn.sendall(f"{server_message}|{r}|{s}".encode())

    # Receive and verify client's message
    client_data = conn.recv(4096).decode()
    parts = client_data.split('|')
    client_message = parts[0]
    client_r, client_s = int(parts[1]), int(parts[2])

    print(f"\n[SERVER] Received from client:")
    print(f"  Message: {client_message}")
    print(f"  Signature (r, s): ({client_r}, {client_s})")

    is_valid = verify_signature(client_message, (client_r, client_s), client_public_key)
    print(f"\n[SERVER] Signature Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")

    conn.close()
    server_socket.close()
    print("\n[SERVER] Connection closed.")


def run_client(host='127.0.0.1', port=5002):

    print("ELGAMAL DIGITAL SIGNATURE CLIENT")


    public_key, private_key = generate_elgamal_keys()
    p, g, y = public_key
    print(f"\n[CLIENT] Public Key:")
    print(f"  p = {p}")
    print(f"  g = {g}")
    print(f"  y = {y}")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"\n[CLIENT] Connected to {host}:{port}")

    # Receive server's public key
    server_key_data = client_socket.recv(4096).decode()
    server_p, server_g, server_y = map(int, server_key_data.split(','))
    server_public_key = (server_p, server_g, server_y)
    print(f"\n[CLIENT] Received Server Public Key:")
    print(f"  p = {server_p}")
    print(f"  g = {server_g}")
    print(f"  y = {server_y}")

    # Send public key
    client_socket.sendall(f"{p},{g},{y}".encode())

    # Receive and verify server's message
    server_data = client_socket.recv(4096).decode()
    parts = server_data.split('|')
    server_message = parts[0]
    server_r, server_s = int(parts[1]), int(parts[2])

    print(f"\n[CLIENT] Received from server:")
    print(f"  Message: {server_message}")
    print(f"  Signature (r, s): ({server_r}, {server_s})")

    is_valid = verify_signature(server_message, (server_r, server_s), server_public_key)
    print(f"\n[CLIENT] Signature Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")

    # Sign and send message
    client_message = input("\n[CLIENT] Enter message to sign and send: ")
    r, s = sign_message(client_message, private_key)
    print(f"[CLIENT] Signature (r, s): ({r}, {s})")

    client_socket.sendall(f"{client_message}|{r}|{s}".encode())

    client_socket.close()
    print("\n[CLIENT] Connection closed.")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  Server: python elgamal_digital_signature.py server")
        print("  Client: python elgamal_digital_signature.py client")
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "server":
        run_server()
    elif mode == "client":
        run_client()
    else:
        print("Invalid mode. Use 'server' or 'client'")