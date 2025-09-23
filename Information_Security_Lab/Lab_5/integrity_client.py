"""Simple TCP client to send data to the integrity server and verify the returned hash."""
import socket
from hash_fn import hash_hex

HOST = '127.0.0.1'
PORT = 65432


def send_message(message: str, tamper: bool = False):
    data = message.encode('utf-8')
    if tamper:
        # Simulate tampering by flipping a byte in the middle
        b = bytearray(data)
        if len(b) == 0:
            b = bytearray(b'X')
        else:
            b[len(b)//2] ^= 0x01
        data = bytes(b)

    # Send with a 4-byte big-endian length prefix
    length_prefix = len(data).to_bytes(4, 'big')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(length_prefix + data)

        # Read until newline from server (server sends hash + '\n')
        resp = b''
        while not resp.endswith(b'\n'):
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk

    server_hash = resp.decode('ascii').strip() if resp else None

    # Compute local hash on the original message (not tampered) to simulate
    # what the sender believes was sent. In practice the sender would hash
    # the exact bytes it transmitted; here we intentionally compare to
    # the non-tampered message when tamper=True to show mismatch.
    local_hash = hash_hex(message)

    print('Original message:', repr(message))
    print('Tampered during transit:' , tamper)
    print('Local hash: ', local_hash)
    print('Server hash:', server_hash)

    if server_hash == local_hash:
        print('Integrity check: OK — data unchanged')
    else:
        print('Integrity check: FAILED — data was corrupted or tampered')


if __name__ == '__main__':
    msg = input('Enter message to send: ')
    choice = input('Tamper in transit? (y/N): ').strip().lower()
    tamper = choice == 'y'
    send_message(msg, tamper)
