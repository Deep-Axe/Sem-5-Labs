#!/usr/bin/env python3

import socket
import hashlib
import random
from math import gcd


# RSA Key Generation
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


def generate_prime(bits=512):
    """Generate a random prime number"""
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1
        if is_prime(num):
            return num


def mod_inverse(a, m):
    """Extended Euclidean Algorithm for modular inverse"""
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m


def generate_rsa_keys(bits=512):
    """Generate RSA public and private keys"""
    print("Generating RSA keys...")
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Common public exponent
    d = mod_inverse(e, phi)
    return (e, n), (d, n)


def hash_message(message):
    """Create SHA-256 hash of message"""
    return int(hashlib.sha256(message.encode()).hexdigest(), 16)


def sign_message(message, private_key):
    """Sign a message using RSA private key"""
    d, n = private_key
    message_hash = hash_message(message)
    signature = pow(message_hash, d, n)
    return signature


def verify_signature(message, signature, public_key):
    """Verify RSA signature"""
    e, n = public_key
    message_hash = hash_message(message)
    decrypted_hash = pow(signature, e, n)
    return message_hash == decrypted_hash


# Server Implementation
def run_server(host='127.0.0.1', port=5001):

    print("RSA DIGITAL SIGNATURE SERVER")


    # Generate server's RSA keys
    public_key, private_key = generate_rsa_keys()
    print(f"\n[SERVER] Public Key (e, n): ({public_key[0]}, {public_key[1]})")
    print(f"[SERVER] Private Key (d, n): (Hidden, {private_key[1]})")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f"\n[SERVER] Listening on {host}:{port}...")

    conn, addr = server_socket.accept()
    print(f"\n[SERVER] Connected by {addr}")

    # Send public key to client
    conn.sendall(f"{public_key[0]},{public_key[1]}".encode())

    # Receive client's public key
    client_public_key_data = conn.recv(4096).decode()
    client_e, client_n = map(int, client_public_key_data.split(','))
    client_public_key = (client_e, client_n)
    print(f"\n[SERVER] Received Client Public Key: ({client_e}, {client_n})")

    # Sign a message and send to client
    server_message = input("\n[SERVER] Enter message to sign and send: ")
    signature = sign_message(server_message, private_key)
    print(f"[SERVER] Message Hash: {hash_message(server_message)}")
    print(f"[SERVER] Digital Signature: {signature}")

    # Send message and signature
    conn.sendall(f"{server_message}|{signature}".encode())

    # Receive client's message and signature
    client_data = conn.recv(4096).decode()
    client_message, client_signature = client_data.split('|')
    client_signature = int(client_signature)

    print(f"\n[SERVER] Received from client:")
    print(f"  Message: {client_message}")
    print(f"  Signature: {client_signature}")

    # Verify client's signature
    is_valid = verify_signature(client_message, client_signature, client_public_key)
    print(f"\n[SERVER] Signature Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")

    conn.close()
    server_socket.close()
    print("\n[SERVER] Connection closed.")


# Client Implementation
def run_client(host='127.0.0.1', port=5001):

    print("RSA DIGITAL SIGNATURE CLIENT")


    # Generate client's RSA keys
    public_key, private_key = generate_rsa_keys()
    print(f"\n[CLIENT] Public Key (e, n): ({public_key[0]}, {public_key[1]})")
    print(f"[CLIENT] Private Key (d, n): (Hidden, {private_key[1]})")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"\n[CLIENT] Connected to {host}:{port}")

    # Receive server's public key
    server_public_key_data = client_socket.recv(4096).decode()
    server_e, server_n = map(int, server_public_key_data.split(','))
    server_public_key = (server_e, server_n)
    print(f"\n[CLIENT] Received Server Public Key: ({server_e}, {server_n})")

    # Send client's public key
    client_socket.sendall(f"{public_key[0]},{public_key[1]}".encode())

    # Receive server's message and signature
    server_data = client_socket.recv(4096).decode()
    server_message, server_signature = server_data.split('|')
    server_signature = int(server_signature)

    print(f"\n[CLIENT] Received from server:")
    print(f"  Message: {server_message}")
    print(f"  Signature: {server_signature}")

    # Verify server's signature
    is_valid = verify_signature(server_message, server_signature, server_public_key)
    print(f"\n[CLIENT] Signature Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")

    # Sign a message and send to server
    client_message = input("\n[CLIENT] Enter message to sign and send: ")
    signature = sign_message(client_message, private_key)
    print(f"[CLIENT] Message Hash: {hash_message(client_message)}")
    print(f"[CLIENT] Digital Signature: {signature}")

    # Send message and signature
    client_socket.sendall(f"{client_message}|{signature}".encode())

    client_socket.close()
    print("\n[CLIENT] Connection closed.")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  Server: python rsa_digital_signature.py server")
        print("  Client: python rsa_digital_signature.py client")
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "server":
        run_server()
    elif mode == "client":
        run_client()
    else:
        print("Invalid mode. Use 'server' or 'client'")