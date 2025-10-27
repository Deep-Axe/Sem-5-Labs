"""Client that sends a message in multiple parts to the server, receives
the SHA-256 hash of the reassembled message, and verifies integrity.

This script demonstrates splitting an arbitrary bytes message into parts
and sending as base64-encoded JSON PART messages.
"""
import socket
import json
import base64
import hashlib
import uuid
import time
from typing import List


def split_bytes(b: bytes, part_size: int) -> List[bytes]:
    return [b[i:i+part_size] for i in range(0, len(b), part_size)]


def send_recv(sock, obj, expect_json=True):
    sock.sendall((json.dumps(obj) + "\n").encode('utf-8'))
    buf = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf += chunk
        if b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            try:
                return json.loads(line.decode('utf-8'))
            except Exception:
                return None


def run_client(host='127.0.0.1', port=9001, message: bytes = None, part_size: int = 10):
    if message is None:
        message = b"This is a test message that we will split into multiple parts and send to the server to check integrity.\n"
    parts = split_bytes(message, part_size)
    msg_id = str(uuid.uuid4())
    with socket.create_connection((host, port), timeout=5) as sock:
        # BEGIN
        resp = send_recv(sock, {"cmd": "BEGIN", "msg_id": msg_id, "parts": len(parts)})
        print('BEGIN ->', resp)

        # send parts out of order to show server reassembly by index
        order = list(range(len(parts)))
        # for demonstration shuffle order (but keep deterministic for tests)
        # we'll do a simple reordering: send even indices first, then odds
        order = [i for i in order if i % 2 == 0] + [i for i in order if i % 2 == 1]

        for i in order:
            b64 = base64.b64encode(parts[i]).decode('utf-8')
            resp = send_recv(sock, {"cmd": "PART", "msg_id": msg_id, "index": i, "data": b64})
            print(f'PART {i} ack ->', resp)
            time.sleep(0.05)

        # after all parts server should send hash response; read until we get it
        # The server already sends the hash as soon as all parts are present and will have been received
        # by our recv calls above; to be robust, wait briefly then try to read any trailing response
        time.sleep(0.1)
        # Try to receive one more response if available (non-blocking would be better but keep simple)
        try:
            sock.settimeout(1.0)
            buf = sock.recv(4096)
            if buf:
                # may contain one or more newline-terminated JSONs; parse last
                lines = [l for l in buf.split(b"\n") if l]
                last = json.loads(lines[-1].decode('utf-8'))
            else:
                last = None
        except Exception:
            last = None

        if last:
            print('Server final response ->', last)
            if last.get('ok') and last.get('hash'):
                server_hash = last.get('hash')
                local_hash = hashlib.sha256(message).hexdigest()
                print('Local hash:', local_hash)
                if server_hash == local_hash:
                    print('Integrity verified: hashes match')
                else:
                    print('Integrity FAILED: hashes differ')
        else:
            print('No final hash response received')


if __name__ == '__main__':
    run_client()
