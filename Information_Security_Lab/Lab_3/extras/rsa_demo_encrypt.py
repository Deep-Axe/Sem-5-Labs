msg = "Cryptographic Protocols"
n = 323
e = 5
d = 173

def encrypt_charwise(message, e, n):
    cipher = []
    for ch in message:
        m = ord(ch)
        if m >= n:
            raise ValueError(f"Plaintext integer {m} for char {ch!r} >= modulus n={n}")
        c = pow(m, e, n)
        cipher.append(c)
    return cipher

def decrypt_charwise(cipher, d, n):
    out = []
    for c in cipher:
        m = pow(c, d, n)
        out.append(chr(m))
    return ''.join(out)


if __name__ == '__main__':
    print('Message:', msg)
    cipher = encrypt_charwise(msg, e, n)
    print('Ciphertext (per-char ints):')
    print(cipher)
    pt = decrypt_charwise(cipher, d, n)
    print('Decrypted plaintext:', pt)
