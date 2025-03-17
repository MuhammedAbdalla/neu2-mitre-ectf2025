#ifndef ECTF_CRYPTO_HELPER_H
#define ECTF_CRYPTO_HELPER_H

#include <stdbool.h>

#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/hash.h"

#define BLOCK_SIZE AES_BLOCK_SIZE
#define KEY_SIZE 32 
#define HASH_SIZE 32 

#include "common.h"

void generate_secrets(char *secret);

void hex_dump(uint8_t* data, size_t len, char* tmp);

uint8_t* rle_decode(const uint8_t* encoded_data, size_t encoded_len, size_t* decoded_len);

int encrypt_cbc_aes256(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext, uint8_t *iv);

int decrypt_cbc_aes256(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext, uint8_t *iv);

int verify_hmac_sha256(uint8_t *hmac, uint8_t *key, uint8_t *message, size_t message_len, bool compute);

#endif // ECTF_CRYPTO_HELPER_H
