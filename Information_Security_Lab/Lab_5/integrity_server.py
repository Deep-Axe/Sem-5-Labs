"""Simple TCP server that receives a message, computes its 32-bit hash, and
returns the hex hash to the client. Demonstrates integrity-checking.
"""
import socket
from hash_fn import hash_hex

HOST = '127.0.0.1'
PORT = 65432


def recv_exact(conn, n):
    """Receive exactly n bytes from conn or raise RuntimeError on EOF."""
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise RuntimeError('connection closed')
        buf += chunk
    return buf


def handle_client(conn, addr):
    print(f'Connected by {addr}')
    try:
        # Read 4-byte big-endian length prefix
        raw_len = recv_exact(conn, 4)
        msg_len = int.from_bytes(raw_len, 'big')
        data = recv_exact(conn, msg_len)

        # Compute hash using local hash function and send back as ASCII hex
        try:
            text = data.decode('utf-8')
        except Exception:
            # If decoding fails, compute hash on raw bytes by decoding as latin-1
            text = data.decode('latin-1')

        h = hash_hex(text)
        conn.sendall((h + '\n').encode('ascii'))
        print(f'Received {msg_len} bytes, hash={h} sent back')
    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f'Server listening on {HOST}:{PORT} ...')
        try:
            while True:
                conn, addr = s.accept()
                handle_client(conn, addr)
        except KeyboardInterrupt:
            print('\nServer shutting down')


if __name__ == '__main__':
    main()
