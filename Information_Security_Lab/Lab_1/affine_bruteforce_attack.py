from math import gcd

def affine_decrypt(ciphertext, a, b):
    m = 26
    try:
        a_inv = pow(a, -1, m)
    except ValueError:
        return None
    result = []
    for c in ciphertext:
        if c.isalpha():
            y = ord(c.upper()) - ord('A')
            x = (a_inv * (y - b)) % m
            result.append(chr(x + ord('A')))
        else:
            result.append(c)
    return ''.join(result)

def brute_force_affine(ciphertext, known_ptext, known_ctext):
    m = 26
    x1, x2 = ord(known_ptext[0].upper()) - ord('A'), ord(known_ptext[1].upper()) - ord('A')
    y1, y2 = ord(known_ctext[0].upper()) - ord('A'), ord(known_ctext[1].upper()) - ord('A')
    for a in range(1, m):
        if gcd(a, m) != 1:
            continue
        for b in range(m):
            t1 = (a * x1 + b) % m
            t2 = (a * x2 + b) % m
            if t1 == y1 and t2 == y2:
                decrypted = affine_decrypt(ciphertext, a, b)
                print(f"a={a}, b={b}: {decrypted}")

def main():
    ciphertext = input("Enter ciphertext to decrypt: ").strip()
    known_ptext = input("Enter known plaintext (e.g. ab): ").strip()
    known_ctext = input("Enter ciphertext of known plaintext (e.g. GL): ").strip()
    brute_force_affine(ciphertext, known_ptext, known_ctext)

if __name__ == "__main__":
    main()