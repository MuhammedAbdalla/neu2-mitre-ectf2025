"""
Author: Based on Ben Janis's work
Date: 2025
This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!
Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse
import json
import binascii
import struct
from pathlib import Path
from loguru import logger
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import HMAC, SHA256


def gen_subscription(secrets: bytes, device_id: int, start: int, end: int, channel: int) -> bytes:
    """Generate the contents of a subscription.

    This function creates an encrypted and authenticated subscription packet for a decoder,
    using keys derived from a master key and salt, consistent with simple_crypto.c and decoder.c.

    Args:
        secrets (bytes): JSON-encoded secrets containing master_key and master_salt.
        device_id (int): Unique identifier for the target decoder.
        start (int): Start timestamp of the subscription.
        end (int): End timestamp of the subscription.
        channel (int): Channel number to subscribe to.

    Returns:
        bytes: Encrypted subscription data appended with an HMAC for authentication.
    """
    # Load the JSON of the secrets file
    secrets_json = json.loads(secrets)
    
    # Load the master key with fallback to 'aes_key'
    if "master_key" in secrets_json:
        master_key = binascii.unhexlify(secrets_json["master_key"])
    else:
        master_key = binascii.unhexlify(secrets_json["aes_key"])
    
    # Load the master salt with fallback to default
    if "master_salt" in secrets_json:
        master_salt = binascii.unhexlify(secrets_json["master_salt"])
    else:
        master_salt = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 18, 19])
    
    keys = derive_keys(master_key, master_salt, device_id)
    
    # Pack the subscription data in little-endian format: device_id (uint32_t), start (uint64_t), end (uint64_t), channel (uint32_t)
    subscription_data = struct.pack("<IQQI", device_id, start, end, channel)
    
    iv = generate_iv(keys['sub slt'], device_id)
    
    # Encrypt with AES-CBC using the derived subscription encryption key
    cipher = AES.new(keys['sub enc'], AES.MODE_CBC, iv=iv)
    
    # Pad the data to AES block size (16 bytes)
    padded_data = pad(subscription_data, AES.block_size)
    
    # Encrypt the padded subscription data
    encrypted = cipher.encrypt(padded_data)
    
    # Generate HMAC using the derived subscription authentication key
    h = HMAC.new(keys['sub aut'], digestmod=SHA256)
    h.update(encrypted)
    hmac_tag = h.digest()
    
    # Return the encrypted data concatenated with the HMAC
    return encrypted + hmac_tag


def derive_keys(master_key, master_salt, device_id):
    """Derive all keys for a specific device ID.

    This function replicates the key derivation function (kdf_derive_keys) from simple_crypto.c,
    generating video and subscription encryption, authentication, and salt keys.

    Args:
        master_key (bytes): 32-byte master key.
        master_salt (bytes): 14-byte master salt.
        device_id (int): Device identifier used as context.

    Returns:
        dict: Dictionary mapping key labels to their derived values.
    """
    # Labels for key derivation
    video_enc_label = b'vid enc'
    video_auth_label = b'vid aut'
    video_salt_label = b'vid slt'
    sub_enc_label = b'sub enc'
    sub_auth_label = b'sub aut'
    sub_salt_label = b'sub slt'
    
    labels = [video_enc_label, video_auth_label, video_salt_label,
              sub_enc_label, sub_auth_label, sub_salt_label]
    
    # Dictionary to store derived keys
    derived_keys = {}
    
    # Derive each key
    for label in labels:
        # Create context with device_id + label
        context = struct.pack("<I", device_id) + label
        
        # Initialize IV with salt (BLOCK_SIZE = 16 bytes)
        iv = bytearray(16)
        for j in range(min(len(master_salt), 16)):
            iv[j] = master_salt[j]
        
        # XOR context into IV
        for j in range(min(len(context), 16)):
            iv[j % 16] ^= context[j]
        
        # Key size: 16 bytes for salts, 32 bytes for encryption/auth keys
        key_size = 16 if label.endswith(b'slt') else 32
        key_material = b''
        
        # Generate key material using AES-ECB as a Pseudo-Random Function (PRF)
        for i in range(0, key_size, 16):
            # Add counter to IV (incrementing last byte per block)
            iv[15] = (i // 16)
            
            # Use AES-ECB with master key to generate key material
            cipher = AES.new(master_key, AES.MODE_ECB)
            key_material += cipher.encrypt(bytes(iv))
        
        # Store the derived key, truncated to required size
        derived_keys[label.decode('utf-8')] = key_material[:key_size]
    
    return derived_keys


def generate_iv(salt, packet_index):
    """Generate IV from salt and packet index.

    This function mirrors the generate_iv function in simple_crypto.c, creating an IV
    by XORing the last 4 bytes of the salt with the packet index.

    Args:
        salt (bytes): 16-byte salt (e.g., derived sub_salt).
        packet_index (int): Value to XOR into the IV (e.g., device_id).

    Returns:
        bytes: 16-byte IV for AES encryption.
    """
    iv = bytearray(salt)
    
    # XOR the last 4 bytes with packet_index (little-endian order)
    for i in range(4):
        iv[12 + i] ^= (packet_index >> (24 - i * 8)) & 0xFF
    
    return bytes(iv)


def parse_args():
    """Define and parse the command line arguments.

    NOTE: Your design must not change this function as it is required by the eCTF framework.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of subscription file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=argparse.FileType("rb"),
        help="Path to the secrets file created by ectf25_design.gen_secrets",
    )
    parser.add_argument("subscription_file", type=Path, help="Subscription output")
    parser.add_argument(
        "device_id", type=lambda x: int(x, 0), help="Device ID of the update recipient."
    )
    parser.add_argument(
        "start", type=lambda x: int(x, 0), help="Subscription start timestamp"
    )
    parser.add_argument("end", type=int, help="Subscription end timestamp")
    parser.add_argument("channel", type=int, help="Channel to subscribe to")
    return parser.parse_args()


def main():
    """Main function of gen_subscription.

    This function orchestrates the subscription generation process, parsing arguments
    and writing the result to a file. You will likely not have to change this function.
    """
    # Parse the command line arguments
    args = parse_args()
    
    # Generate the subscription packet
    subscription = gen_subscription(
        args.secrets_file.read(), args.device_id, args.start, args.end, args.channel
    )

    # NOTE: Printing sensitive data is not recommended for security-critical applications
    logger.debug(f"Generated subscription: {subscription.hex()}")
    
    # Write to the subscription file, using 'wb' to overwrite if --force is set, else 'xb' to avoid overwriting
    with open(args.subscription_file, "wb" if args.force else "xb") as f:
        f.write(subscription)
    
    logger.success(f"Wrote subscription to {str(args.subscription_file.absolute())}")


if __name__ == "__main__":
    main()
