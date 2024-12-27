import hashlib

def hash_word_md5():
    # Prompt the user to enter a word
    word = input("ENTER WORD: ")
    
    # Create an MD5 hash object
    md5_hash = hashlib.md5()
    
    # Update the hash object with the word (encoded to bytes)
    md5_hash.update(word.encode('utf-8'))
    
    # Print the hexadecimal representation of the hash
    print("MD5 Hash:", md5_hash.hexdigest())

# Call the function to run the tool
hash_word_md5()
