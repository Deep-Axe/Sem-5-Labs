#!/usr/bin/env python3
import socket
import hashlib
import hmac
import random


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


def generate_dh_parameters():
    """Generate Diffie-Hellman parameters"""
    print("Generating Diffie-Hellman parameters...")
    p = generate_prime(256)
    g = random.randint(2, p - 2)
    return p, g


def generate_private_key(p):
    """Generate private key for DH"""
    return random.randint(2, p - 2)


def generate_public_key(g, private_key, p):
    """Generate public key for DH"""
    return pow(g, private_key, p)


def compute_shared_secret(other_public_key, private_key, p):
    """Compute shared secret"""
    return pow(other_public_key, private_key, p)


def sign_message_hmac(message, shared_secret):
    """Create HMAC signature using shared secret"""
    key = str(shared_secret).encode()
    signature = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    return signature


def verify_signature_hmac(message, signature, shared_secret):
    """Verify HMAC signature"""
    key = str(shared_secret).encode()
    expected_signature = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected_signature)


def run_server(host='127.0.0.1', port=5004):
    """Diffie-Hellman + HMAC Server"""

    print("DIFFIE-HELLMAN KEY EXCHANGE + HMAC SIGNATURE SERVER")


    # Generate DH parameters
    p, g = generate_dh_parameters()
    print(f"\n[SERVER] DH Parameters:")
    print(f"  p = {p}")
    print(f"  g = {g}")

    # Generate server's private and public keys
    server_private = generate_private_key(p)
    server_public = generate_public_key(g, server_private, p)
    print(f"\n[SERVER] Private Key: {server_private}")
    print(f"[SERVER] Public Key: {server_public}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f"\n[SERVER] Listening on {host}:{port}...")

    conn, addr = server_socket.accept()
    print(f"\n[SERVER] Connected by {addr}")

    # Send DH parameters and public key
    conn.sendall(f"{p},{g},{server_public}".encode())

    # Receive client's public key
    client_public = int(conn.recv(4096).decode())
    print(f"\n[SERVER] Received Client Public Key: {client_public}")

    # Compute shared secret
    shared_secret = compute_shared_secret(client_public, server_private, p)
    print(f"[SERVER] Computed Shared Secret: {shared_secret}")

    # Sign and send message
    server_message = input("\n[SERVER] Enter message to sign and send: ")
    signature = sign_message_hmac(server_message, shared_secret)
    print(f"[SERVER] HMAC Signature: {signature}")

    conn.sendall(f"{server_message}|{signature}".encode())

    # Receive and verify client's message
    client_data = conn.recv(4096).decode()
    client_message, client_signature = client_data.split('|')

    print(f"\n[SERVER] Received from client:")
    print(f"  Message: {client_message}")
    print(f"  Signature: {client_signature}")

    is_valid = verify_signature_hmac(client_message, client_signature, shared_secret)
    print(f"\n[SERVER] Signature Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")

    conn.close()
    server_socket.close()
    print("\n[SERVER] Connection closed.")


def run_client(host='127.0.0.1', port=5004):

    print("DIFFIE-HELLMAN KEY EXCHANGE + HMAC SIGNATURE CLIENT")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"\n[CLIENT] Connected to {host}:{port}")

    # Receive DH parameters and server's public key
    dh_data = client_socket.recv(4096).decode()
    p, g, server_public = map(int, dh_data.split(','))
    print(f"\n[CLIENT] Received DH Parameters:")
    print(f"  p = {p}")
    print(f"  g = {g}")
    print(f"[CLIENT] Received Server Public Key: {server_public}")

    # Generate client's private and public keys
    client_private = generate_private_key(p)
    client_public = generate_public_key(g, client_private, p)
    print(f"\n[CLIENT] Private Key: {client_private}")
    print(f"[CLIENT] Public Key: {client_public}")

    # Send client's public key
    client_socket.sendall(str(client_public).encode())

    # Compute shared secret
    shared_secret = compute_shared_secret(server_public, client_private, p)
    print(f"[CLIENT] Computed Shared Secret: {shared_secret}")

    # Receive and verify server's message
    server_data = client_socket.recv(4096).decode()
    server_message, server_signature = server_data.split('|')

    print(f"\n[CLIENT] Received from server:")
    print(f"  Message: {server_message}")
    print(f"  Signature: {server_signature}")

    is_valid = verify_signature_hmac(server_message, server_signature, shared_secret)
    print(f"\n[CLIENT] Signature Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")

    # Sign and send message
    client_message = input("\n[CLIENT] Enter message to sign and send: ")
    signature = sign_message_hmac(client_message, shared_secret)
    print(f"[CLIENT] HMAC Signature: {signature}")

    client_socket.sendall(f"{client_message}|{signature}".encode())

    client_socket.close()
    print("\n[CLIENT] Connection closed.")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  Server: python diffie_hellman_signature.py server")
        print("  Client: python diffie_hellman_signature.py client")
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "server":
        run_server()
    elif mode == "client":
        run_client()
    else:
        print("Invalid mode. Use 'server' or 'client'")
