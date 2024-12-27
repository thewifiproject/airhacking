import hashlib

def hash_word():
    # Prompt the user to enter a word
    word = input("ENTER WORD: ")
    
    # Create a SHA-1 hash object
    sha1_hash = hashlib.sha1()
    
    # Update the hash object with the word (encoded to bytes)
    sha1_hash.update(word.encode('utf-8'))
    
    # Print the hexadecimal representation of the hash
    print("SHA-1 Hash:", sha1_hash.hexdigest())

# Call the function to run the tool
hash_word()
