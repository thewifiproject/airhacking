import winreg

def decode_key(encoded_key):
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

def get_product_key():
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        encoded_key = winreg.QueryValueEx(registry_key, "DigitalProductId")[0]
        return decode_key(list(encoded_key))
    except Exception as e:
        return f"Error retrieving product key: {e}"

if __name__ == "__main__":
    print("Windows Product Key:", get_product_key())
