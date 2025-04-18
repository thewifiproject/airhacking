import winreg

# Function to decode the product key from the encoded format
def decode_product_key(encoded_key):
    chars = "BCDFGHJKMPQRTVWXY2346789"
    key = []
    for i in range(29, -1, -1):
        accumulator = 0
        for j in range(14, -1, -1):
            accumulator = accumulator * 256
            accumulator += encoded_key[j + 52]
            encoded_key[j + 52] = accumulator // 24
            accumulator %= 24
        key.insert(0, chars[accumulator])
        if i % 6 == 0 and i != 0:
            key.insert(0, '-')
    return ''.join(key)

# Function to retrieve the product key from the registry
def get_windows_product_key():
    try:
        # Open the registry key where the Windows product key is stored
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        
        # Query the DigitalProductId value
        encoded_key = winreg.QueryValueEx(registry_key, "DigitalProductId")[0]
        
        # Decode the key and return it
        return decode_product_key(list(encoded_key))
    except Exception as e:
        return f"Error retrieving product key: {e}"

if __name__ == "__main__":
    product_key = get_windows_product_key()
    print(f"Windows Product Key: {product_key}")
