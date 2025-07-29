def encrypt(name, s):
    res = ""
    for i in range(len(name)):
        char = name[i]
        if char.isupper():
            res += chr(((ord(char) - 65) * s) % 26 + 65)
        elif char.islower():
            res += chr(((ord(char) - 97) * s) % 26 + 97)
        else:
            res += char
    return res

def decrypt(name, s):
    res = ""
    try:
        multiplicative_inverse = pow(s, -1, 26)
    except ValueError:
        return "Invalid key, no modular inverse exists"
    for i in range(len(name)):
        char = name[i]
        if char.isupper():
            res += chr(((ord(char) - 65) * multiplicative_inverse) % 26 + 65)
        elif char.islower():
            res += chr(((ord(char) - 97) * multiplicative_inverse) % 26 + 97)
        else:
            res += char
    return res

def main():
    while True:
        choice = input("Enter encrypt or decrypt using multiplicative cipher or exit out of prg: ")
        if choice == "encrypt":
            name = input("Enter plain Text : ")
            s = int(input("Enter key: "))
            result = encrypt(name, s)
        elif choice == "decrypt":
            name = input("Enter plain Text : ")
            s = int(input("Enter key: "))
            result = decrypt(name, s)
        elif choice == "exit":
            break
        else:
            print("invalid choice")
            continue
        print("Resultant encryption/decryption is ", result)

if __name__ == '__main__':
    main()

