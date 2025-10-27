"""Simple JSON-over-TCP server for PKSE demo.

Commands (JSON, newline-terminated):
- STORE: {"cmd":"STORE","index":{word:[hex_cipher,...]},"docs":{id:base64_blob,...}}
- SEARCH: {"cmd":"SEARCH","word":"..."}
- GETDOC: {"cmd":"GETDOC","doc_id":int}

Responses are JSON objects newline-terminated. Successful responses include
an "ok": true field and additional data.
"""
import socket
import threading
import json
import base64
from typing import Dict, List


class InMemoryStore:
    def __init__(self):
        # word -> list of hex ciphertext strings
        self.enc_index: Dict[str, List[str]] = {}
        # doc_id -> base64 blob
        self.docs: Dict[int, str] = {}

    def store(self, index: Dict[str, List[str]], docs: Dict[str, str]):
        # merge index (append postings)
        for w, lst in (index or {}).items():
            self.enc_index.setdefault(w, [])
            # avoid duplicates
            for c in lst:
                if c not in self.enc_index[w]:
                    self.enc_index[w].append(c)

        for k, v in (docs or {}).items():
            try:
                kid = int(k)
            except Exception:
                continue
            self.docs[kid] = v


def handle_connection(conn, addr, store: InMemoryStore):
    buf = b''
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
                        req = json.loads(line.decode('utf-8'))
                    except Exception as e:
                        resp = {"ok": False, "error": f"invalid json: {e}"}
                        conn.sendall((json.dumps(resp) + "\n").encode('utf-8'))
                        continue

                    cmd = req.get('cmd')
                    if cmd == 'STORE':
                        store.store(req.get('index'), req.get('docs'))
                        resp = {"ok": True, "msg": "stored"}
                        conn.sendall((json.dumps(resp) + "\n").encode('utf-8'))
                    elif cmd == 'SEARCH':
                        word = req.get('word')
                        if word is None:
                            resp = {"ok": False, "error": "missing word"}
                        else:
                            lst = store.enc_index.get(word, [])
                            resp = {"ok": True, "postings": lst}
                        conn.sendall((json.dumps(resp) + "\n").encode('utf-8'))
                    elif cmd == 'GETDOC':
                        doc_id = req.get('doc_id')
                        if doc_id is None:
                            resp = {"ok": False, "error": "missing doc_id"}
                        else:
                            blob = store.docs.get(int(doc_id))
                            if blob is None:
                                resp = {"ok": False, "error": "not found"}
                            else:
                                resp = {"ok": True, "blob": blob}
                        conn.sendall((json.dumps(resp) + "\n").encode('utf-8'))
                    else:
                        resp = {"ok": False, "error": "unknown cmd"}
                        conn.sendall((json.dumps(resp) + "\n").encode('utf-8'))
    except Exception:
        # keep server simple: don't crash on single-connection errors
        pass


def run_server(host='127.0.0.1', port=9998):
    store = InMemoryStore()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    print(f'PKSE server listening on {host}:{port}')
    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_connection, args=(conn, addr, store), daemon=True)
            t.start()
    finally:
        sock.close()


if __name__ == '__main__':
    run_server()
