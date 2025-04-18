#! /usr/bin/env python
#  -*- coding: utf-8 -*-


import winreg
import wmi

# This function is derived from https://gist.github.com/Spaceghost/877110
def decode_key(rpk):
    rpkOffset = 52
    i = 28
    szPossibleChars = "BCDFGHJKMPQRTVWXY2346789"
    szProductKey = ""

    while i >= 0:
        dwAccumulator = 0
        j = 14
        while j >= 0:
            dwAccumulator = dwAccumulator * 256
            d = rpk[j + rpkOffset]
            if isinstance(d, str):
                d = ord(d)
            dwAccumulator = d + dwAccumulator
            rpk[j + rpkOffset] = int(dwAccumulator / 24) if int(dwAccumulator / 24) <= 255 else 255
            dwAccumulator = dwAccumulator % 24
            j = j - 1
        i = i - 1
        szProductKey = szPossibleChars[dwAccumulator] + szProductKey

        if ((29 - i) % 6) == 0 and i != -1:
            i = i - 1
            szProductKey = "-" + szProductKey
    return szProductKey


def get_key_from_reg_location(key, value='DigitalProductID'):
    arch_keys = [0, winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY]
    for arch in arch_keys:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ | arch)
            value, type = winreg.QueryValueEx(key, value)
            # Return the first match
            return decode_key(list(value))
        except (FileNotFoundError, TypeError) as e:
            pass


def get_windows_product_key_from_reg():
    return get_key_from_reg_location(r'SOFTWARE\Microsoft\Windows NT\CurrentVersion')


def get_windows_product_key_from_wmi():
    w = wmi.WMI()
    try:
        product_key = w.softwarelicensingservice()[0].OA3xOriginalProductKey
        if product_key != '':
            return product_key
        else:
            return None
    except AttributeError:
        return None


if __name__ == '__main__':
    print('Key from WMI: %s' % get_windows_product_key_from_wmi())
