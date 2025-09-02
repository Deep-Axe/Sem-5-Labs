def mod_inverse(a, m):
    # Compute modular inverse of a under modulo m
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def affine_decrypt(ciphertext, a, b):
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return None
    plaintext = ""
    for c in ciphertext:
        if c.isalpha():
            y = ord(c.upper()) - ord('A')
            x = (a_inv * (y - b)) % 26
            plaintext += chr(x + ord('a'))
        else:
            plaintext += c
    return plaintext

ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
a, b = 5, 6  # from known plaintext "ab" -> "GL"

plaintext = affine_decrypt(ciphertext, a, b)
print("Decrypted Text:", plaintext)
