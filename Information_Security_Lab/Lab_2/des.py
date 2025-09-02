import binascii
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Function to encrypt a message using DES in ECB mode
def encrypt_des(message, key):
    """
    Encrypts a plaintext message using DES.
    Pads the message to a multiple of 8 bytes and converts ciphertext to hex.
    """
    # Ensure key is exactly 8 bytes (DES requirement)
    if len(key) < 8:
        key = key.ljust(8, '0')  # pad with zeros if shorter
    elif len(key) > 8:
        key = key[:8]  # truncate if longer
    key_bytes = key.encode('utf-8')  # convert to bytes
    message_bytes = message.encode('utf-8')

    cipher = DES.new(key_bytes, DES.MODE_ECB)  # create DES cipher in ECB mode

    padded_message = pad(message_bytes, DES.block_size)  # PKCS7 padding
    ciphertext = cipher.encrypt(padded_message)  # encrypt message

    # Convert ciphertext to hexadecimal string for easy display
    ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8').upper()

    return ciphertext_hex

# Function to decrypt a DES-encrypted hex string
def decrypt_des(ciphertext_hex, key):
    """
    Decrypts a DES-encrypted message given in hex format.
    Unpads the plaintext to recover the original message.
    """
    try:
        # Ensure key is exactly 8 bytes
        if len(key) < 8:
            key = key.ljust(8, '0')
        elif len(key) > 8:
            key = key[:8]

        key_bytes = key.encode('utf-8')

        ciphertext = binascii.unhexlify(ciphertext_hex)  # convert hex to bytes

        cipher = DES.new(key_bytes, DES.MODE_ECB)  # create DES cipher

        decrypted_padded = cipher.decrypt(ciphertext)  # decrypt ciphertext
        decrypted_message = unpad(decrypted_padded, DES.block_size).decode('utf-8')  # remove padding

        return decrypted_message

    except Exception as e:
        return f"Decryption failed: {str(e)}"

# Main interactive program
def main():
    """
    Provides a menu to encrypt/decrypt messages using DES or exit the program.
    Handles input, key adjustments, and displays results.
    """
    print("DES Encryption/Decryption System")

    while True:
        choice = input("Enter encrypt or decrypt using DES cipher or exit out of prg: ")

        if choice == "encrypt":
            message = input("Enter plain text: ")
            key = input("Enter key (8 characters): ")
            result = encrypt_des(message, key)
            # Show the actual key used after padding/truncating
            print("Key used:", key if len(key) == 8 else (key.ljust(8, '0') if len(key) < 8 else key[:8]))

        elif choice == "decrypt":
            ciphertext_hex = input("Enter ciphertext (in hex): ")
            key = input("Enter key (8 characters): ")
            result = decrypt_des(ciphertext_hex, key)
            # Show the actual key used after padding/truncating
            print("Key used:", key if len(key) == 8 else (key.ljust(8, '0') if len(key) < 8 else key[:8]))

        elif choice == "exit":
            break

        else:
            print("Invalid choice")
            continue

        print("Resultant encryption/decryption is:", result)
        print()

if __name__ == '__main__':
    main()
