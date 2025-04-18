import winreg

def get_product_key():
    key = winreg.HKEY_LOCAL_MACHINE
    subkey = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    value_name = "DigitalProductId"

    try:
        registry_key = winreg.OpenKey(key, subkey)
        product_id = winreg.QueryValueEx(registry_key, value_name)[0]
        return decode_product_key(product_id)
    except WindowsError:
        return None

def decode_product_key(digital_product_id):
    key = []
    for i in range(0, 15):
        current = digital_product_id[i + 52]
        current = current ^ 0x36
        key.append(current)

    decoded_key = ''.join([chr(x) for x in key])
    return decoded_key

if __name__ == "__main__":
    product_key = get_product_key()
    if product_key:
        print("Your Windows Product Key is:", product_key)
    else:
        print("Unable to retrieve the product key.")
