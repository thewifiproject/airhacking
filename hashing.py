import hashlib

def hash_word():
    print("Choose a hashing algorithm:")
    print("1. MD5")
    print("2. SHA-1")
    print("3. SHA-256")
    print("4. SHA-512")
    
    choice = input("Enter your choice (1-4): ")
    word = input("ENTER WORD: ")
    
    if choice == "1":
        hashed = hashlib.md5(word.encode('utf-8')).hexdigest()
        algorithm = "MD5"
    elif choice == "2":
        hashed = hashlib.sha1(word.encode('utf-8')).hexdigest()
        algorithm = "SHA-1"
    elif choice == "3":
        hashed = hashlib.sha256(word.encode('utf-8')).hexdigest()
        algorithm = "SHA-256"
    elif choice == "4":
        hashed = hashlib.sha512(word.encode('utf-8')).hexdigest()
        algorithm = "SHA-512"
    else:
        print("Invalid choice. Please select 1-4.")
        return
    
    print(f"{algorithm} Hash:", hashed)

# Call the function to run the tool
hash_word()
