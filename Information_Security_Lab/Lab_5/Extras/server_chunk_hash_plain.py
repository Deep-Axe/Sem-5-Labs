"""Plain-text protocol server for chunked message hashing.

Protocol (line-delimited text):
- Client sends: BEGIN:<msg_id>:<parts>\n
- Server replies: ACK-BEGIN:<msg_id>\n
- Client sends parts: PART:<msg_id>:<index>:<base64_data>\n
- Server replies for each part: ACK-PART:<msg_id>:<index>\n
- When all parts received server sends: HASH:<msg_id>:<hex_digest>\n

This server prints detailed step-by-step logs to stdout so you can
observe the workflow on the server side.
"""
import socket
import threading
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
    print(f"[SERVER] Connection from {addr}")
    buf = b''
    buffers: Dict[str, MessageBuffer] = {}
    try:
        with conn:
            while True:
                data = conn.recv(4096)
                if not data:
                    print(f"[SERVER] Connection closed by {addr}")
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode('utf-8').strip()
                    if not text:
                        continue
                    print(f"[SERVER] Received: {text}")
                    # parse simple text protocol
                    if text.startswith('BEGIN:'):
                        try:
                            _, msg_id, parts_s = text.split(':', 2)
                            parts = int(parts_s)
                        except Exception:
                            conn.sendall(b"ERR:INVALID-BEGIN\n")
                            continue
                        buffers[msg_id] = MessageBuffer(parts)
                        ack = f"ACK-BEGIN:{msg_id}\n".encode('utf-8')
                        conn.sendall(ack)
                        print(f"[SERVER] BEGIN ack for {msg_id}, expecting {parts} parts")
                    elif text.startswith('PART:'):
                        try:
                            _, msg_id, index_s, b64 = text.split(':', 3)
                            index = int(index_s)
                            data_bytes = base64.b64decode(b64)
                        except Exception:
                            conn.sendall(b"ERR:INVALID-PART\n")
                            continue
                        if msg_id not in buffers:
                            conn.sendall(b"ERR:UNKNOWN-MSG\n")
                            continue
                        buffers[msg_id].add_part(index, data_bytes)
                        ack = f"ACK-PART:{msg_id}:{index}\n".encode('utf-8')
                        conn.sendall(ack)
                        print(f"[SERVER] Stored part {index} for {msg_id}")
                        if buffers[msg_id].is_complete():
                            assembled = buffers[msg_id].assemble()
                            digest = hashlib.sha256(assembled).hexdigest()
                            resp = f"HASH:{msg_id}:{digest}\n".encode('utf-8')
                            conn.sendall(resp)
                            print(f"[SERVER] All parts received for {msg_id}, sent HASH {digest}")
                            del buffers[msg_id]
                    else:
                        conn.sendall(b"ERR:UNKNOWN-CMD\n")
    except Exception as e:
        print(f"[SERVER] Connection handler error: {e}")


def run_server(host='127.0.0.1', port=9002):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    print(f"[SERVER] Plain-text chunk server listening on {host}:{port}")
    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_conn, args=(conn, addr), daemon=True)
            t.start()
    finally:
        sock.close()


if __name__ == '__main__':
    run_server()
