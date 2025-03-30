import argparse
import struct
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256

def derive_keys(secrets) -> (bytearray, bytearray, bytearray, bytearray, bytearray, bytearray):
    array = bytearray(ord(char) for char in secrets)

    kve = hmac_sha256(array, array[0:32])
    kse = hmac_sha256(array, array[5:37])
    kfe = hmac_sha256(array, array[10:42])

    kva = hmac_sha256(array, array[15:47])
    ksa = hmac_sha256(array, array[20:52])
    kfa = hmac_sha256(array, array[25:57])

    return (kve, kse, kfe, kva, ksa, kfa)

def rle_encode(data: bytearray) -> bytearray:
    if not data:
        return bytearray()

    encoded = bytearray()
    current_byte = data[0]
    count = 1

    for i in range(1, len(data)):
        if data[i] == current_byte and count < 255: # Limit count to 255
            count += 1
        else:
            encoded.append(count)
            encoded.append(current_byte)
            current_byte = data[i]
            count = 1

    encoded.append(count)
    encoded.append(current_byte)

    return encoded

def hmac_sha256(message: bytearray, key: bytearray) -> bytearray:
    try:
        h = HMAC.new(key, digestmod=SHA256)
        h.update(message)
        return bytearray(h.digest())
    except ValueError as e:
        print(f"HMAC error: {e}")
        return None
    except TypeError as e:
        print(f"Type error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def encrypt_cbc_aes256(plaintext: bytearray, key: bytearray, iv: bytearray) -> bytearray:
    try:
        block_size = AES.block_size
        if len(plaintext) % block_size != 0:
            plaintext.extend([0] * (block_size - (len(plaintext) % block_size)))
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(bytes(plaintext))
        return bytearray(ciphertext)
    except ValueError as e:
        print(f"Encryption error: {e}")
        return None
    except KeyError as e:
        print(f"Key error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

    return None

