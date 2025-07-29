def encrypt(name, s):
    res = ""
    for i in range(len(name)):
        char = name[i]
        if char.isupper():
            res += chr((ord(char) +s-65)%26 + 65)
        elif char.islower():
            res += chr((ord(char) +s-97)%26 + 97)
        else:
            res += char
    return res

def decrypt(name, s):
    res = ""
    for i in range(len(name)):
        char = name[i]
        if char.isupper():
            res += chr((ord(char) - s - 65) % 26 + 65)
        elif char.islower():
            res += chr((ord(char) - s - 97) % 26 + 97)
        else:
            res += char
    return res

def main():
    while True:
        choice = input("Enter encrypt or decrypt using additive/ceasar cipher or exit out of prg: ")
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

