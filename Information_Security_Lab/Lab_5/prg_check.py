from Crypto.Cipher import AES

def print_hex(label, data):
    print(f"{label}: {data.hex()}")

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
    print_hex("Decrypted", decrypted)
    print("Decrypted PT:", decrypted)
    print()

def aes256_ctr_demo():
    print("AES-256 CTR")
    pt = b'1' * 16
    key = b'25625625625625625625625625625625'  
    nonce = b''  
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=0)
    ct = cipher.encrypt(pt)

    cipher_dec = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=0)
    decrypted = cipher_dec.decrypt(ct)

    print_hex("Plaintext", pt)
    print_hex("Key", key)
    print_hex("Ciphertext", ct)
    print("Mode: CTR")
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
