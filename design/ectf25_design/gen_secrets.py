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
import json
from pathlib import Path

from loguru import logger


def gen_secrets(channels: list[int]) -> bytes:
    """Generate the contents secrets file

    This function generates a JSON-encoded secrets file containing a master key, master salt,
    and a list of valid channels. The secrets are used by the Encoder, gen_subscription, and
    the Decoder build process for cryptographic operations.

    Args:
        channels (list[int]): List of channel numbers that will be valid in this deployment.
            Channel 0 is the emergency broadcast, which will always be valid and is NOT included
            in this list.

    Returns:
        bytes: JSON-encoded contents of the secrets file.
    """
    master_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    
    master_salt = "0001020304050607080910111213"
    
    # Create the secrets object
    secrets = {
        "channels": channels,
        "master_key": master_key,
        "master_salt": master_salt,
        # Keep the old key for backward compatibility
        "aes_key": master_key 
    }
    
    # Encode the secrets as JSON and return as bytes
    return json.dumps(secrets).encode()


def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function as it is required by the eCTF framework.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
        " be provided in this list",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    This function orchestrates the secrets generation process, parsing arguments and writing
    the result to a file. You will likely not have to change this function.
    """
    args = parse_args()

    # Generate the secrets
    secrets = gen_secrets(args.channels)

    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated secrets: {secrets}")

    # Open the file, using 'wb' to overwrite if --force is set, else 'xb' to avoid overwriting
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        f.write(secrets)

    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()