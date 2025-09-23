from Crypto.Cipher import AES

def print_hex(label, data):
    print(f"{label}: {data.hex()}")


def get_aes_variant(key: bytes) -> str:
    """Return which AES variant the key corresponds to based on length.

    AES key sizes are:
      - 16 bytes -> AES-128
      - 24 bytes -> AES-192
      - 32 bytes -> AES-256
    """
    l = len(key)
    if l == 16:
        return 'AES-128'
    if l == 24:
        return 'AES-192'
    if l == 32:
        return 'AES-256'
    return f'Invalid AES key length: {l} bytes'

def aes128_cbc_demo():
    print("AES-128 CBC")
    pt = b'1' * 16
    key = b'1281281281281281' 
    iv = b'0' * 16           

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pt)

    cipher_dec = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher_dec.decrypt(ct)

    print_hex("Plaintext", pt)
    print_hex("Key", key)
    print_hex("IV", iv)
    print_hex("Ciphertext", ct)
    print("Mode: CBC")
    print("Detected variant:", get_aes_variant(key))
    print_hex("Decrypted", decrypted)
    print("Decrypted PT:", decrypted)
    print()

def aes192_cfb_demo():
    print("AES-192 CFB")
    pt = b'1' * 16
    key = b'192192192192192192192192'  
    iv = b'0' * 16                    

    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    ct = cipher.encrypt(pt)

    cipher_dec = AES.new(key, AES.MODE_CFB, iv=iv)
    decrypted = cipher_dec.decrypt(ct)

    print_hex("Plaintext", pt)
    print_hex("Key", key)
    print_hex("IV", iv)
    print_hex("Ciphertext", ct)
    print("Mode: CFB")
    print("Detected variant:", get_aes_variant(key))
    print_hex("Decrypted", decrypted)
    print("Decrypted PT:", decrypted)
    print()

def aes192_ofb_demo():
    print("AES-192 OFB")
    pt = b'1' * 16
    key = b'192192192192192192192192'  
    iv = b'0' * 16                  

    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    ct = cipher.encrypt(pt)

    cipher_dec = AES.new(key, AES.MODE_OFB, iv=iv)
    decrypted = cipher_dec.decrypt(ct)

    print_hex("Plaintext", pt)
    print_hex("Key", key)
    print_hex("IV", iv)
    print_hex("Ciphertext", ct)
    print("Mode: OFB")
    print("Detected variant:", get_aes_variant(key))
    print_hex("Decrypted", decrypted)
    print("Decrypted PT:", decrypted)
    print()

def aes256_ctr_demo():
    print("AES-256 CTR")
    pt = b'1' * 16
    # Make sure the key is 32 bytes long for AES-256. Here we construct
    # a 32-byte key by repeating the ASCII sequence '256' ten times (30 bytes)
    # and appending '25' to reach 32 bytes. You can replace this with any
    # secure 32-byte key in real use.
    key = (b'256' * 10) + b'25'
    nonce = b''  
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=0)
    ct = cipher.encrypt(pt)

    cipher_dec = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=0)
    decrypted = cipher_dec.decrypt(ct)

    print_hex("Plaintext", pt)
    print_hex("Key", key)
    print_hex("Ciphertext", ct)
    print("Mode: CTR")
    print("Detected variant:", get_aes_variant(key))
    print_hex("Decrypted", decrypted)
    print("Decrypted PT:", decrypted)
    print()

def main():
    aes128_cbc_demo()
    aes192_cfb_demo()
    aes192_ofb_demo()
    aes256_ctr_demo()

if __name__ == "__main__":
    main()
