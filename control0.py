import winreg
import base64
import binascii

def decode_product_key(registry_key):
    # This function decodes the product key from the registry
    key = ''.join([chr(int(registry_key[i:i+2], 16)) for i in range(0, len(registry_key), 2)])
    decoded_key = ''.join([key[i] for i in range(24) if i % 2 == 0])
    return decoded_key

def get_product_key():
    try:
        # Access the registry where the product key is stored
        registry_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        registry_value_name = "DigitalProductId"

        # Open the registry key
        reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
        
        # Read the DigitalProductId value
        product_id = winreg.QueryValueEx(reg, registry_value_name)[0]

        # Extract and decode the product key
        decoded_key = decode_product_key(binascii.hexlify(product_id[52:66]).decode())
        
        return decoded_key
    except Exception as e:
        return f"An error occurred: {e}"

# Call the function and print the result
print(get_product_key())
