"""Interactive plain-text client for chunked-hash server.

This client prompts the user for a message and part size, then sends
BEGIN and PART lines using a simple text protocol (no JSON). It prints
the step-by-step workflow on the client side and verifies the SHA-256
hash returned by the server matches the locally computed hash.
"""
import socket
import base64
import hashlib
import uuid
import time


def split_bytes(b: bytes, part_size: int):
    return [b[i:i+part_size] for i in range(0, len(b), part_size)]


def recv_line(sock):
    buf = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf += chunk
        if b"\n" in buf:
            line, rest = buf.split(b"\n", 1)
            return line.decode('utf-8').strip()


def run_interactive(host='127.0.0.1', port=9002):
    print('Interactive chunked-hash client')
    msg = input('Enter message to send (single line):\n')
    if not msg:
        print('Empty message; aborting')
        return
    try:
        part_size = int(input('Enter part size in bytes (e.g. 10): '))
    except Exception:
        part_size = 10

    parts = split_bytes(msg.encode('utf-8'), part_size)
    msg_id = str(uuid.uuid4())

    print(f'Connecting to {host}:{port}...')
    with socket.create_connection((host, port), timeout=5) as sock:
        begin_line = f'BEGIN:{msg_id}:{len(parts)}\n'
        print(f'[CLIENT] -> {begin_line.strip()}')
        sock.sendall(begin_line.encode('utf-8'))
        ack = recv_line(sock)
        print('[CLIENT] <-', ack)

        # send parts in a visible order (even then odd)
        order = [i for i in range(len(parts)) if i % 2 == 0] + [i for i in range(len(parts)) if i % 2 == 1]
        for i in order:
            b64 = base64.b64encode(parts[i]).decode('utf-8')
            part_line = f'PART:{msg_id}:{i}:{b64}\n'
            print(f'[CLIENT] -> PART {i} ({len(parts[i])} bytes)')
            sock.sendall(part_line.encode('utf-8'))
            ack = recv_line(sock)
            print('[CLIENT] <-', ack)
            time.sleep(0.05)

        print('[CLIENT] Waiting for HASH response...')
        # read until we get a HASH line
        while True:
            line = recv_line(sock)
            if line is None:
                print('[CLIENT] Connection closed without HASH')
                break
            print('[CLIENT] <-', line)
            if line.startswith('HASH:'):
                _, mid, digest = line.split(':', 2)
                local = hashlib.sha256(msg.encode('utf-8')).hexdigest()
                print('[CLIENT] Local SHA-256:', local)
                if digest == local:
                    print('[CLIENT] Integrity verified: hashes match')
                else:
                    print('[CLIENT] Integrity FAILED: hashes differ')
                break


if __name__ == '__main__':
    run_interactive()
