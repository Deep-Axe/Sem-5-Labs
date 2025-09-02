# Classical Cipher Program: Vigenère + Autokey Cipher
# Includes encryption and decryption with detailed comments

def vigenere_encrypt(plaintext, key):
    """
    Encrypts plaintext using the Vigenère cipher.
    Each letter is shifted by the corresponding key letter (repeated).
    """
    ciphertext = ""
    key = key.upper()
    key_index = 0  # To track position in key
    for char in plaintext:
        if char.isalpha():
            # Normalize to uppercase A=0...Z=25
            shift = ord(key[key_index % len(key)]) - ord('A')
            # Apply shift preserving case
            base = ord('A') if char.isupper() else ord('a')
            ciphertext += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1  # Move to next key character only for letters
        else:
            ciphertext += char
    return ciphertext


def vigenere_decrypt(ciphertext, key):
    """
    Decrypts ciphertext using the Vigenère cipher.
    Subtracts key shifts instead of adding them.
    """
    plaintext = ""
    key = key.upper()
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            plaintext += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            plaintext += char
    return plaintext


def autokey_encrypt(plaintext, key):
    """
    Encrypts plaintext using the Autokey cipher.
    Key is extended by appending the plaintext itself.
    """
    ciphertext = ""
    key = key.upper() + plaintext.upper()  # Extend key with plaintext
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            ciphertext += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            ciphertext += char
    return ciphertext


def autokey_decrypt(ciphertext, key):
    """
    Decrypts ciphertext using the Autokey cipher.
    The key must be reconstructed dynamically while decrypting.
    """
    plaintext = ""
    key = key.upper()
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            # Compute shift from current key letter
            shift = ord(key[key_index]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            # Undo the shift
            p = chr((ord(char) - base - shift) % 26 + base)
            plaintext += p
            # Append recovered plaintext to key (autokey property)
            key += p.upper()
            key_index += 1
        else:
            plaintext += char
    return plaintext


def main():
    """
    Main driver function to choose between Vigenère and Autokey cipher.
    Handles encryption and decryption based on user input.
    """
    while True:
        print("\nChoose the cipher:")
        print("1. Vigenère Cipher")
        print("2. Autokey Cipher")
        print("3. Exit")
        
        choice = input("Enter choice (1/2/3): ")
        
        if choice == "3":
            print("Exiting program...")
            break
        
        mode = input("Do you want to encrypt or decrypt? ").lower()
        text = input("Enter the text: ")
        key = input("Enter the key (string): ")
        
        if choice == "1":  # Vigenère Cipher
            if mode == "encrypt":
                print("Result:", vigenere_encrypt(text, key))
            else:
                print("Result:", vigenere_decrypt(text, key))
        
        elif choice == "2":  # Autokey Cipher
            if mode == "encrypt":
                print("Result:", autokey_encrypt(text, key))
            else:
                print("Result:", autokey_decrypt(text, key))
        
        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()
