def encrypt(name, s):
    res = ""
    keyword = s.lower()
    s_len = len(s)
    key_ind = [ord(key) - 97 for key in keyword]
    i = 0
    for char in name:
        if char.isupper():
            shift_key = key_ind[i % s_len]
            res += chr((ord(char) - 65 + shift_key) % 26 + 65)
            i += 1
        elif char.islower():
            shift_key = key_ind[i % s_len]
            res += chr((ord(char) - 97 + shift_key) % 26 + 97)
            i += 1
        else:
            res += char
    return res

def decrypt(name, s):
    res = ""
    keyword = s.lower()
    s_len = len(s)
    key_ind = [ord(key) - 97 for key in keyword]
    i = 0
    for char in name:
        if char.isupper():
            shift_key = key_ind[i % s_len]
            res += chr((ord(char) - 65 - shift_key + 26) % 26 + 65)
            i += 1
        elif char.islower():
            shift_key = key_ind[i % s_len]
            res += chr((ord(char) - 97 - shift_key + 26) % 26 + 97)
            i += 1
        else:
            res += char


    return res


def main():
    while True:
        choice = input("Enter encrypt or decrypt using vigenere cipher or exit out of prg: ")
        if choice == "encrypt":
            name = input("Enter plain Text : ")
            s = input("Enter keyword: ")
            result = encrypt(name, s)
        elif choice == "decrypt":
            name = input("Enter plain Text : ")
            s = input("Enter keyword: ")
            result = decrypt(name, s)
        elif choice == "exit":
            break
        else:
            print("invalid choice")
            continue
        print("Resultant encryption/decryption is ", result)

if __name__ == '__main__':
    main()

