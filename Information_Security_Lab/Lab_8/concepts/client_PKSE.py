"""PKSE client demo that uses Information_Security_Lab/Lab_8/pkse.py

Flow:
- Generate Paillier keypair
- Build encrypted index (word -> [hex ciphertexts])
- Connect to server and STORE index + docs
- SEARCH for some words, receive encrypted postings, decrypt locally
- GETDOC for returned doc IDs and display document content
"""
import socket
import json
import base64
import pathlib
import sys

# make sure Lab_8 is on path so we can import pkse.py
HERE = pathlib.Path(__file__).resolve().parents[1]
sys.path.append(str(HERE))

from pkse import generate_dataset, generate_paillier, build_encrypted_index, decrypt_postings


def send_recv(sock, obj):
    data = (json.dumps(obj) + "\n").encode('utf-8')
    sock.sendall(data)
    # read a single newline-terminated JSON response
    buf = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if b"\n" in buf:
            line, _ = buf.split(b"\n", 1)
            try:
                return json.loads(line.decode('utf-8'))
            except Exception:
                return {"ok": False, "error": "invalid json response"}
    return {"ok": False, "error": "no response"}


def run_client(host='127.0.0.1', port=9998):
    docs = generate_dataset()
    print('Preparing dataset and keys...')
    pub, priv = generate_paillier(1024)
    enc_index = build_encrypted_index(docs, pub)

    # prepare docs map as base64 text blobs
    docs_blobs = {str(i): base64.b64encode(docs[i].encode('utf-8')).decode('utf-8') for i in range(len(docs))}

    with socket.create_connection((host, port), timeout=5) as sock:
        print('Storing encrypted index and docs on server...')
        resp = send_recv(sock, {"cmd": "STORE", "index": enc_index, "docs": docs_blobs})
        print('STORE ->', resp)

        # perform searches
        queries = ['paillier', 'python', 'data', 'encryption', 'hashing']
        for q in queries:
            print(f"\nSEARCH '{q}' ->")
            resp = send_recv(sock, {"cmd": "SEARCH", "word": q})
            if not resp.get('ok'):
                print('  error:', resp.get('error'))
                continue
            postings = resp.get('postings', [])
            if not postings:
                print('  no results')
                continue
            print('  Encrypted postings (hex):', postings)
            ids = decrypt_postings(postings, priv)
            print('  Decrypted doc IDs:', ids)
            for doc_id in ids:
                g = send_recv(sock, {"cmd": "GETDOC", "doc_id": doc_id})
                if g.get('ok') and g.get('blob'):
                    blob = base64.b64decode(g['blob']).decode('utf-8')
                    print(f'   {doc_id}: {blob}')
                else:
                    print('   failed to fetch doc', doc_id, g)


if __name__ == '__main__':
    run_client()
