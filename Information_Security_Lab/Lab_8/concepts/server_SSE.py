"""Simple SSE server.

Protocol (JSON-over-TCP, newline-terminated messages):
- STORE: client uploads encrypted index and encrypted docs.
  {"cmd":"STORE","index":{token: {nonce,ct,tag}},"docs":{id: {nonce,ct,tag}}}
- SEARCH: client asks for token -> server returns the encrypted posting blob (nonce,ct,tag)
  {"cmd":"SEARCH","token":"..."}
- GETDOC: client requests encrypted document by id
  {"cmd":"GETDOC","doc_id": 3}

Server responses: JSON with 'status' ('ok'|'error') and payload fields.
This is a demo server (in-memory storage).
"""

import socketserver
import json
import base64


def b64ify_blob(blob: dict) -> dict:
	return {
		'nonce': base64.b64encode(blob['nonce']).decode(),
		'ct': base64.b64encode(blob['ct']).decode(),
		'tag': base64.b64encode(blob['tag']).decode()
	}


def unb64ify_blob(bdict: dict) -> dict:
	return {
		'nonce': base64.b64decode(bdict['nonce']),
		'ct': base64.b64decode(bdict['ct']),
		'tag': base64.b64decode(bdict['tag'])
	}


class SSEStorage:
	def __init__(self):
		self.index = {}  # token -> blob (dict with nonce,ct,tag as bytes)
		self.docs = {}   # doc_id (str) -> blob


STORAGE = SSEStorage()


class Handler(socketserver.StreamRequestHandler):
	def handle(self):
		# Read newline-terminated JSON commands
		while True:
			line = self.rfile.readline()
			if not line:
				break
			try:
				req = json.loads(line.decode())
			except Exception as e:
				self.wfile.write(json.dumps({'status': 'error', 'error': 'invalid json'}).encode() + b"\n")
				continue

			cmd = req.get('cmd')
			if cmd == 'STORE':
				# store index and docs (received as base64-encoded blobs)
				idx = req.get('index', {})
				docs = req.get('docs', {})
				for token, blob in idx.items():
					STORAGE.index[token] = unb64ify_blob(blob)
				for did, blob in docs.items():
					STORAGE.docs[str(did)] = unb64ify_blob(blob)
				self.wfile.write(json.dumps({'status': 'ok'}).encode() + b"\n")

			elif cmd == 'SEARCH':
				token = req.get('token')
				blob = STORAGE.index.get(token)
				if not blob:
					self.wfile.write(json.dumps({'status': 'ok', 'found': False}).encode() + b"\n")
				else:
					# return base64-encoded blob
					b64 = b64ify_blob(blob)
					self.wfile.write(json.dumps({'status': 'ok', 'found': True, 'blob': b64}).encode() + b"\n")

			elif cmd == 'GETDOC':
				doc_id = str(req.get('doc_id'))
				blob = STORAGE.docs.get(doc_id)
				if not blob:
					self.wfile.write(json.dumps({'status': 'error', 'error': 'doc not found'}).encode() + b"\n")
				else:
					b64 = b64ify_blob(blob)
					self.wfile.write(json.dumps({'status': 'ok', 'blob': b64}).encode() + b"\n")

			else:
				self.wfile.write(json.dumps({'status': 'error', 'error': 'unknown cmd'}).encode() + b"\n")


def run_server(host='127.0.0.1', port=9999):
	with socketserver.ThreadingTCPServer((host, port), Handler) as srv:
		print(f'SSE server listening on {host}:{port}')
		try:
			srv.serve_forever()
		except KeyboardInterrupt:
			print('\nServer stopped')


if __name__ == '__main__':
	run_server()

