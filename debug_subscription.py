from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import HMAC, SHA256
import struct
import binascii

aes_key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
aes_key = binascii.unhexlify(aes_key_hex)


device_id = 0xDEADBEEF
start_timestamp = 0
end_timestamp = 0xFFFFFFFFFFFFFFFF
channel = 1

subscription_data = struct.pack("<IQQI", device_id, start_timestamp, end_timestamp, channel)

# Encrypt with AES-ECB
cipher = AES.new(aes_key, AES.MODE_ECB)
padded_data = pad(subscription_data, AES.block_size)
encrypted = cipher.encrypt(padded_data)

# Generate HMAC
h = HMAC.new(aes_key, digestmod=SHA256)
h.update(encrypted)
hmac_tag = h.digest()

subscription = encrypted + hmac_tag

print(f"Generated subscription: {subscription.hex()}")
print(f"Length: {len(subscription)} bytes")
print(f"Encrypted data: {encrypted.hex()} ({len(encrypted)} bytes)")
print(f"HMAC tag: {hmac_tag.hex()} ({len(hmac_tag)} bytes)")

with open("debug_subscription.bin", "wb") as f:
    f.write(subscription)

print("Wrote subscription to debug_subscription.bin")
