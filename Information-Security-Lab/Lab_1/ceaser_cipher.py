def encrypt(name, s):
    # Use a breakpoint in the code line below to debug your script.
    res = ""  # Press Ctrl+F8 to toggle the breakpoint.
    for i in range(len(name)):
        char = name[i]
        if char.isupper():
            res += chr((ord(char) +s-65)%26 + 65)
        elif char.islower():
            res += chr((ord(char) +s-97)%26 + 97)
    return res

def decrypt(name, s):
  pass
  
def main():
    name = input("Enter plain Text: ")
    s = int(input("Enter key: "))
    choice = input("Enter encrypt or decrypt: ")
    result = ''
    if choice == "encrypt":
        result = encrypt(name, s)
    elif choice == "decrypt":
        result = decrypt(name, s)
    print("Resultant encryption/decryption is ", result)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()

