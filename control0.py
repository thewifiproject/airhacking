import winreg
import binascii

def get_product_key():
    try:
        # Open the registry key where the product key is stored
        registry_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        registry_value_name = "DigitalProductId"

        # Open the registry key
        reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)

        # Read the DigitalProductId value, it is binary data
        product_id = winreg.QueryValueEx(reg, registry_value_name)[0]

        # The product key is stored starting from the 52nd byte (index 52)
        key = product_id[52:67]

        # Decode the key
        product_key = ''.join([str(x) for x in key])

        return product_key
    except Exception as e:
        return f"An error occurred: {e}"

# Call the function and print the result
print(get_product_key())
