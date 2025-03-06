import json
import base64
import sys
import os

def decode_string_bytes(input: str):
    imm = base64.b64decode(input.encode('utf-8'))
    return '\"'+"".join(f"\\x{byte:02x}" for byte in imm) + '\"'

def generate_header(input_file, header_file):
    # Open the input file in read mode
    with open(input_file, 'r') as file:
        secrets = json.loads(file.read())

    # Open the header file in write mode
    with open(header_file, 'w') as header:
        # Write the necessary C includes and data structure
        header.write('\n#ifndef SECRETS_H\n#define SECRETS_H\n')
        
        lines = []
        enums = []
        # Convert each line from the file to a C string and write to the header file
        for packet in ["video", "subscription"]:
            for field in ["key", "iv", "auth"]:
                e = f"{packet.upper()}_{field.upper()}"
                l = decode_string_bytes(secrets[packet][field])
                lines.append(l)
                enums.append(e)


        header.write(f'\nconst char *secrets[] = {{\n{",\n".join(lines)} \n}};\n')

        # create the typedef enum
        header.write(f'\ntypedef enum {{\n{",\n".join(enums)} \n}} secret_enums;\n')

        header.write('\n#endif // SECRETS_H\n')

    print(f"Header file '{header_file}' created successfully!")

if __name__ == "__main__":
    # set working directory to the script
    os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))
    print("working in", os.getcwd())
    # Define input and output file names
    # docker container compile
    value = os.getenv('COMPILETIME')

    if value is not None and value == 'DOCKER':
        # i will be in container /decoder
        input_file = "/global.secrets"
        header_file = "../inc/secrets.h"
    else:
        # i will be project top level
        input_file = '../../secrets/global.secrets'  # The text file you want to embed
        header_file = '../inc/secrets.h'  # The generated C header file

    # Generate the header file
    generate_header(input_file, header_file)