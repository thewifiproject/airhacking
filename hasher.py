import hashlib

# Ask for the word and hash type input
word = input("ENTER WORD: ")
type_of_hash = input("ENTER TYPE (e.g., sha256, md5, sha1, sha224, sha512): ").lower()

# Create a dictionary to map hash types to their corresponding hashlib functions
hash_algorithms = {
    "sha256": hashlib.sha256,
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha512": hashlib.sha512,
    "sha384": hashlib.sha384,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s
}

# Check if the chosen hash type is valid
if type_of_hash in hash_algorithms:
    # Hash the word using the selected algorithm
    hashed_word = hash_algorithms[type_of_hash](word.encode()).hexdigest()
    print(f"Hashed word ({type_of_hash}):", hashed_word)
else:
    print("Invalid hash type. Please choose from: sha256, md5, sha1, sha224, sha512, sha384, blake2b, blake2s.")
