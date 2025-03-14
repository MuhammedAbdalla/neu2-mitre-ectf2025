"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse
import struct
import json
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import HMAC, SHA256

class Encoder:
    def __init__(self, secrets: bytes):
        """Initialize the encoder with secrets"""
        # Load the json of the secrets file
        secrets_json = json.loads(secrets)
        
        # Load the master key and salt with fallbacks
        if "master_key" in secrets_json:
            self.master_key = binascii.unhexlify(secrets_json["master_key"])
        else:
            # Use legacy key if not provided
            self.master_key = binascii.unhexlify(secrets_json["aes_key"])
        
        if "master_salt" in secrets_json:
            self.master_salt = binascii.unhexlify(secrets_json["master_salt"])
        else:
            # Use a default salt if not provided
            self.master_salt = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 18, 19])
        
        # Cache for derived keys by device_id
        self.key_cache = {}

    def derive_keys(self, device_id):
        """Derive all keys for a specific device ID"""
        if device_id in self.key_cache:
            return self.key_cache[device_id]
        
        # Labels for key derivation
        video_enc_label = b'vid enc'
        video_auth_label = b'vid aut'
        video_salt_label = b'vid slt'
        sub_enc_label = b'sub enc'
        sub_auth_label = b'sub aut'
        sub_salt_label = b'sub slt'
        
        labels = [video_enc_label, video_auth_label, video_salt_label,
                  sub_enc_label, sub_auth_label, sub_salt_label]
        
        # Derived keys
        derived_keys = {}
        
        # Derive each key
        for label in labels:
            # Create context with device_id + label
            context = struct.pack("<I", device_id) + label
            
            # Salt input
            iv = bytearray(16)
            for j in range(min(len(self.master_salt), 16)):
                iv[j] = self.master_salt[j]
            
            for j in range(min(len(context), 16)):
                iv[j % 16] ^= context[j]
            
            # Key size depends on type (16 for salts, 32 for keys)
            key_size = 16 if label.endswith(b'slt') else 32
            key_material = b''
            
            # Generate key material 
            for i in range(0, key_size, 16):
                # Add counter
                iv[15] = (i // 16)
                
                cipher = AES.new(self.master_key, AES.MODE_ECB)
                key_material += cipher.encrypt(bytes(iv))
            
            # Store derived key
            derived_keys[label.decode('utf-8')] = key_material[:key_size]
        
        # Cache the keys
        self.key_cache[device_id] = derived_keys
        return derived_keys

    def generate_iv(self, salt, packet_index):
        """Generate IV from salt and packet index"""
        iv = bytearray(salt)
        
        # XOR with packet index 
        for i in range(4):
            iv[12 + i] ^= (packet_index >> (24 - i * 8)) & 0xFF
        
        return bytes(iv)

    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """The frame encoder function

        This will be called for every frame that needs to be encoded before being
        transmitted by the satellite to all listening TVs

        You **may not** change the arguments or returns of this function!

        :param channel: 32b unsigned channel number. Channel 0 is the emergency
            broadcast that must be decodable by all channels.
        :param frame: Frame to encode. Max frame size is 64 bytes.
        :param timestamp: 64b timestamp to use for encoding. **NOTE**: This value may
            have no relation to the current timestamp, so you should not compare it
            against the current time. The timestamp is guaranteed to strictly
            monotonically increase (always go up) with subsequent calls to encode

        :returns: The encoded frame, which will be sent to the Decoder
        """
        # Pack the header (channel and timestamp)
        header = struct.pack("<IQ", channel, timestamp)
        
        device_id = 0xDEADBEEF
        
        # Derive keys for this device
        keys = self.derive_keys(device_id)
        
        # For emergency channel (0), don't encrypt but still authenticate
        if channel == 0:
            # Generate an HMAC using video auth key
            h = HMAC.new(keys['vid aut'], digestmod=SHA256)
            h.update(header + frame)
            hmac_tag = h.digest()
            
            return header + frame + hmac_tag
        
        # Generate IV from video salt and timestamp 
        iv = self.generate_iv(keys['vid slt'], timestamp)
        
        # For other channels, encrypt using AES-CBC with video enc key
        cipher = AES.new(keys['vid enc'], AES.MODE_CBC, iv=iv)
        
        # Pad the frame to AES block size
        padded_frame = pad(frame, AES.block_size)
        
        # Encrypt the frame
        encrypted_frame = cipher.encrypt(padded_frame)
        
        # Generate an HMAC using video auth key
        h = HMAC.new(keys['vid aut'], digestmod=SHA256)
        h.update(header + encrypted_frame)
        hmac_tag = h.digest()
        
        # Return header + encrypted frame + HMAC
        return header + encrypted_frame + hmac_tag

def main():
    """A test main to one-shot encode a frame

    This function is only for your convenience and will not be used in the final design.

    After pip-installing, you should be able to call this with:
        python3 -m ectf25_design.encoder path/to/test.secrets 1 "frame to encode" 100
    """
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument(
        "secrets_file", type=argparse.FileType("rb"), help="Path to the secrets file"
    )
    parser.add_argument("channel", type=int, help="Channel to encode for")
    parser.add_argument("frame", help="Contents of the frame")
    parser.add_argument("timestamp", type=int, help="64b timestamp to use")
    args = parser.parse_args()

    encoder = Encoder(args.secrets_file.read())
    print(repr(encoder.encode(args.channel, args.frame.encode(), args.timestamp)))

if __name__ == "__main__":
    main()