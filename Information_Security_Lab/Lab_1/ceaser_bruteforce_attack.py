def caesar_find_key(plaintext, ciphertext):
    shifts = []
    for p, c in zip(plaintext, ciphertext):
        if p.isalpha() and c.isalpha():
            shift = (ord(c.upper()) - ord(p.upper())) % 26
            shifts.append(shift)
    if shifts:
        return max(set(shifts), key=shifts.count)
    else:
        raise ValueError("No valid letter pairs found.")

def caesar_decrypt(ciphertext, shift):
    result = []
    for c in ciphertext:
        if c.isalpha():
            idx = (ord(c.upper()) - ord('A') - shift) % 26
            result.append(chr(idx + ord('A')))
        else:
            result.append(c)
    return ''.join(result)

def main():
    known_plain = input("Enter known plaintext: ").strip()
    known_cipher = input("Enter corresponding ciphertext: ").strip()
    mystery_cipher = input("Enter the ciphertext to decrypt: ").strip()

    key = caesar_find_key(known_plain, known_cipher)
    print(f"Discovered Caesar cipher key (shift): {key}")

    decrypted = caesar_decrypt(mystery_cipher, key)
    print(f"Decrypted message: {decrypted}")

if __name__ == "__main__":
    main()