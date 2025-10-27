"""Simple SSE client.

This client builds an encrypted dataset and encrypted index locally (same as
the lab demo), uploads them to the SSE server, then sends SEARCH requests by
token and retrieves encrypted documents using GETDOC. Communication is JSON
over TCP with base64-encoded ciphertext blobs.
"""

import socket
import json
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import string
import json as _json


def normalize(text: str) -> list:
	trans = str.maketrans('', '', string.punctuation)
	cleaned = text.translate(trans).lower()
	return [w for w in cleaned.split() if w]


class ClientSSE:
	def __init__(self, server_host='127.0.0.1', server_port=9999):
		self.server = (server_host, server_port)
		# keys must be kept client-side
		self.doc_key = get_random_bytes(32)
		self.index_key = get_random_bytes(32)
		self.token_key = get_random_bytes(32)

		# local copies for demo
		self.plain_docs = {}

	def token_for_word(self, word: str) -> str:
		h = HMAC.new(self.token_key, digestmod=SHA256)
		h.update(word.encode('utf-8'))
		return h.hexdigest()

	def encrypt_bytes(self, key: bytes, data: bytes) -> dict:
		aesgcm = AES.new(key, AES.MODE_GCM)
		ct, tag = aesgcm.encrypt_and_digest(data)
		return {'nonce': aesgcm.nonce, 'ct': ct, 'tag': tag}

	def b64_blob(self, blob: dict) -> dict:
		return {k: base64.b64encode(v).decode() for k, v in blob.items()}

	def build_and_upload(self, docs: list):
		# encrypt docs and build raw index
		docs_enc = {}
		raw_index = {}
		for i, text in enumerate(docs):
			self.plain_docs[str(i)] = text
			enc = self.encrypt_bytes(self.doc_key, text.encode())
			docs_enc[str(i)] = self.b64_blob(enc)

			for w in normalize(text):
				token = self.token_for_word(w)
				raw_index.setdefault(token, set()).add(i)

		# encrypt postings
		index_enc = {}
		for token, s in raw_index.items():
			postings = json.dumps(sorted(list(s))).encode()
			blob = self.encrypt_bytes(self.index_key, postings)
			index_enc[token] = self.b64_blob(blob)

		# upload via STORE
		req = {'cmd': 'STORE', 'index': index_enc, 'docs': docs_enc}
		resp = self.send_request(req)
		return resp

	def send_request(self, req: dict) -> dict:
		with socket.create_connection(self.server) as sock:
			sock.sendall((json.dumps(req) + '\n').encode())
			data = b''
			# read a line
			while True:
				chunk = sock.recv(4096)
				if not chunk:
					break
				data += chunk
				if b'\n' in data:
					break
			line, _sep, _rest = data.partition(b'\n')
			return json.loads(line.decode())

	def search(self, query: str):
		tokens = [self.token_for_word(w) for w in normalize(query)]
		results = set()
		for token in tokens:
			req = {'cmd': 'SEARCH', 'token': token}
			resp = self.send_request(req)
			if resp.get('status') != 'ok':
				continue
			if not resp.get('found'):
				continue
			blob = resp.get('blob')
			if not blob:
				continue
			# decode blob fields
			blob_bytes = {k: base64.b64decode(v) for k, v in blob.items()}
			# decrypt postings
			cipher = AES.new(self.index_key, AES.MODE_GCM, nonce=blob_bytes['nonce'])
			postings = cipher.decrypt_and_verify(blob_bytes['ct'], blob_bytes['tag'])
			ids = json.loads(postings.decode())
			results.update(ids)

		# fetch documents
		docs = []
		for did in sorted(list(results)):
			req = {'cmd': 'GETDOC', 'doc_id': did}
			resp = self.send_request(req)
			if resp.get('status') != 'ok':
				continue
			blob = resp.get('blob')
			if not blob:
				continue
			blob_bytes = {k: base64.b64decode(v) for k, v in blob.items()}
			cipher = AES.new(self.doc_key, AES.MODE_GCM, nonce=blob_bytes['nonce'])
			pt = cipher.decrypt_and_verify(blob_bytes['ct'], blob_bytes['tag'])
			docs.append((did, pt.decode()))

		return docs


def demo_flow():
	# sample dataset (same as lab)
	docs = [
		"The quick brown fox jumps over the lazy dog",
		"Alice and Bob study cryptography and network security",
		"Symmetric encryption uses the same key for encrypt and decrypt",
		"Searchable encryption allows keyword searches over encrypted data",
		"Python is a popular programming language for security research",
		"Data structures include lists dictionaries sets and tuples",
		"The lab exercises cover AES RSA ECC and hashing algorithms",
		"Design patterns help build maintainable and testable software",
		"Fast hashing functions are used for checksums and bloom filters",
		"Homomorphic and functional encryption are advanced topics"
	]

	client = ClientSSE()
	print('Uploading encrypted docs and index to server...')
	resp = client.build_and_upload(docs)
	print('STORE response:', resp)

	queries = ['encryption', 'python', 'searchable', 'data']
	for q in queries:
		print('\nQuery:', q)
		results = client.search(q)
		if not results:
			print('  no results')
		for did, text in results:
			print(f'  {did}: {text}')


if __name__ == '__main__':
	demo_flow()

