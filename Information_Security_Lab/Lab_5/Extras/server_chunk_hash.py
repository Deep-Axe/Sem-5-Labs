"""Server that receives a message sent in multiple parts, reassembles it,
computes SHA-256 hash, and returns the hex digest to the client.

Protocol (JSON newline-delimited):
- Client sends header: {"cmd":"BEGIN","msg_id":"<id>","parts":N}
- Then client sends N part messages in any order:
  {"cmd":"PART","msg_id":"<id>","index":i,"data":"<base64>"}
- When server has all parts, it computes SHA-256 over the reassembled bytes in index order
  and sends back: {"ok":true,"msg_id":"<id>","hash":"<hex>"}

The server supports multiple simultaneous clients using threads.
"""
import socket
import threading
import json
import base64
import hashlib
from typing import Dict


class MessageBuffer:
    def __init__(self, total_parts: int):
        self.total = total_parts
        self.parts: Dict[int, bytes] = {}

    def add_part(self, index: int, data: bytes):
        if index in self.parts:
            return
        self.parts[index] = data

    def is_complete(self) -> bool:
        return len(self.parts) == self.total

    def assemble(self) -> bytes:
        return b''.join(self.parts[i] for i in sorted(self.parts.keys()))


def handle_conn(conn, addr):
    print('Connection from', addr)
    buf = b''
    # msg_id -> MessageBuffer
    buffers: Dict[str, MessageBuffer] = {}
    try:
        with conn:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line:
                        continue
                    try:
                        obj = json.loads(line.decode('utf-8'))
                    except Exception as e:
                        resp = {"ok": False, "error": f"invalid json: {e}"}
                        conn.sendall((json.dumps(resp) + "\n").encode('utf-8'))
                        continue

                    cmd = obj.get('cmd')
                    if cmd == 'BEGIN':
                        msg_id = obj.get('msg_id')
                        parts = int(obj.get('parts', 0))
                        if not msg_id or parts <= 0:
                            conn.sendall((json.dumps({"ok": False, "error": "invalid BEGIN"}) + "\n").encode('utf-8'))
                            continue
                        buffers[msg_id] = MessageBuffer(parts)
                        conn.sendall((json.dumps({"ok": True, "msg": "begin ack", "msg_id": msg_id}) + "\n").encode('utf-8'))
                    elif cmd == 'PART':
                        msg_id = obj.get('msg_id')
                        index = obj.get('index')
                        b64 = obj.get('data')
                        if msg_id not in buffers:
                            conn.sendall((json.dumps({"ok": False, "error": "unknown msg_id"}) + "\n").encode('utf-8'))
                            continue
                        try:
                            index = int(index)
                            data_bytes = base64.b64decode(b64)
                        except Exception:
                            conn.sendall((json.dumps({"ok": False, "error": "invalid PART"}) + "\n").encode('utf-8'))
                            continue
                        buffers[msg_id].add_part(index, data_bytes)
                        conn.sendall((json.dumps({"ok": True, "msg": "part ack", "msg_id": msg_id, "index": index}) + "\n").encode('utf-8'))
                        if buffers[msg_id].is_complete():
                            assembled = buffers[msg_id].assemble()
                            digest = hashlib.sha256(assembled).hexdigest()
                            resp = {"ok": True, "msg_id": msg_id, "hash": digest}
                            conn.sendall((json.dumps(resp) + "\n").encode('utf-8'))
                            # optionally drop buffer
                            del buffers[msg_id]
                    else:
                        conn.sendall((json.dumps({"ok": False, "error": "unknown cmd"}) + "\n").encode('utf-8'))
    except Exception as e:
        print('Connection handler error:', e)


def run_server(host='127.0.0.1', port=9001):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    print(f'Server listening on {host}:{port}')
    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_conn, args=(conn, addr), daemon=True)
            t.start()
    finally:
        sock.close()


if __name__ == '__main__':
    run_server()
