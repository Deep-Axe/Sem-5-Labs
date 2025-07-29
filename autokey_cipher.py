def encrypt(name, s):
    res = ""
    keyword = s.lower()
    s_len = len(keyword)
    keystream = keyword
    i = 0
    for char in name:
        if char.isalpha():
            if i < s_len:
                shift_key = ord(keystream[i]) - 97
            else:
                shift_key = ord(name[i - s_len].lower()) - 97
            if char.isupper():
                res += chr((ord(char) - 65 + shift_key) % 26 + 65)
            else:
                res += chr((ord(char) - 97 + shift_key) % 26 + 97)
            i += 1
        else:
            res += char
    return res

def decrypt(name, s):
    res = ""
    keyword = s.lower()

    keystream = list(keyword)
    i = 0
    for char in name:
        if char.isalpha():
            shift_key = ord(keystream[i]) - 97
            if char.isupper():
                pt = (ord(char) - 65 - shift_key + 26) % 26
                res_char = chr(pt + 65)
            else:
                pt = (ord(char) - 97 - shift_key + 26) % 26
                res_char = chr(pt + 97)
            res += res_char
            keystream.append(res_char.lower())
            i += 1
        else:
            res += char
    return res

def main():
    while True:
        choice = input("Enter encrypt or decrypt using autokey cipher or exit out of prg: ")
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