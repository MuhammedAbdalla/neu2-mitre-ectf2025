/**
 * @file "simple_crypto.h"
 * @author Ben Janis
 * @brief Simplified Crypto API Header 
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

 #if CRYPTO_EXAMPLE
 #ifndef ECTF_CRYPTO_H
 #define ECTF_CRYPTO_H
 
 #include "wolfssl/wolfcrypt/aes.h"
 #include "wolfssl/wolfcrypt/hash.h"
 #include "wolfssl/wolfcrypt/sha256.h"
 #include "wolfssl/wolfcrypt/hmac.h"
 
 /******************************** MACRO DEFINITIONS ********************************/
 #define BLOCK_SIZE AES_BLOCK_SIZE
 #define KEY_SIZE 32
 #define HASH_SIZE 32
 #define AUTH_KEY_SIZE 32
 #define MASTER_KEY_SIZE 32
 #define MASTER_SALT_SIZE 14
 #define LABEL_SIZE 7
 
/******************************** CONSTANTS ********************************/
 #define VIDEO_ENC_KEY_INDEX 0
 #define VIDEO_AUTH_KEY_INDEX 1
 #define VIDEO_SALT_INDEX 2
 #define SUB_ENC_KEY_INDEX 3
 #define SUB_AUTH_KEY_INDEX 4
 #define SUB_SALT_INDEX 5
 #define NUM_DERIVED_KEYS 6
 
 /******************************** FUNCTION PROTOTYPES ********************************/
 /** @brief Derives multiple keys from a master key using a KDF
  *
  * @param master_key A pointer to the master key (MASTER_KEY_SIZE bytes)
  * @param master_salt A pointer to the master salt (MASTER_SALT_SIZE bytes)
  * @param device_id Unique device identifier
  * @param derived_keys Array of pointers to store NUM_DERIVED_KEYS derived keys
  *
  * @return 0 on success, non-zero on error
  */
 int kdf_derive_keys(const uint8_t *master_key, const uint8_t *master_salt, 
                     uint32_t device_id, uint8_t *derived_keys[NUM_DERIVED_KEYS]);
 
 /** @brief Generates an initialization vector from salt and packet index
  *
  * @param salt A pointer to the salt value
  * @param packet_index The packet sequence number
  * @param iv A pointer to buffer where the IV will be written (BLOCK_SIZE bytes)
  *
  * @return 0 on success, non-zero on error
  */
 int generate_iv(const uint8_t *salt, uint32_t packet_index, uint8_t *iv);
 
 /** @brief Creates an HMAC authentication tag for data
  *
  * @param data A pointer to the data to authenticate
  * @param data_len Length of the data
  * @param key A pointer to the authentication key
  * @param key_len Length of the key
  * @param hmac_out A pointer to buffer where HMAC will be written
  *
  * @return 0 on success, non-zero on error
  */
 int hmac_authenticate(const uint8_t *data, size_t data_len, const uint8_t *key, 
                      size_t key_len, uint8_t *hmac_out);
 
 /** @brief Verifies an HMAC authentication tag for data
  *
  * @param data A pointer to the data to verify
  * @param data_len Length of the data
  * @param key A pointer to the authentication key
  * @param key_len Length of the key
  * @param hmac A pointer to the HMAC to verify against
  *
  * @return 0 on success, non-zero on error
  */
 int hmac_verify(const uint8_t *data, size_t data_len, const uint8_t *key, 
                size_t key_len, const uint8_t *hmac);
 
 /** @brief Encrypts plaintext using a symmetric cipher
  *
  * @param plaintext A pointer to a buffer of length len containing the
  *          plaintext to encrypt
  * @param len The length of the plaintext to encrypt. Must be a multiple of
  *          BLOCK_SIZE (16 bytes)
  * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
  *          the key to use for encryption
  * @param ciphertext A pointer to a buffer of length len where the resulting
  *          ciphertext will be written to
  *
  * @return 0 on success, -1 on bad length, other non-zero for other error
  */
 int encrypt_sym(const uint8_t *plaintext, size_t len, const uint8_t *key, 
    const uint8_t *salt, uint32_t packet_index, uint8_t *ciphertext);
 
 /** @brief Decrypts ciphertext using a symmetric cipher
  *
  * @param ciphertext A pointer to a buffer of length len containing the
  *           ciphertext to decrypt
  * @param len The length of the ciphertext to decrypt. Must be a multiple of
  *           BLOCK_SIZE (16 bytes)
  * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
  *           the key to use for decryption
  * @param plaintext A pointer to a buffer of length len where the resulting
  *           plaintext will be written to
  *
  * @return 0 on success, -1 on bad length, other non-zero for other error
  */
 int decrypt_sym(const uint8_t *ciphertext, size_t len, const uint8_t *key, 
    const uint8_t *salt, uint32_t packet_index, uint8_t *plaintext);
 
 /** @brief Hashes arbitrary-length data
  *
  * @param data A pointer to a buffer of length len containing the data
  *           to be hashed
  * @param len The length of the plaintext to hash
  * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
  *           hash output will be written to
  *
  * @return 0 on success, non-zero for other error
  */
 int hash(void *data, size_t len, uint8_t *hash_out);
 
 #endif // CRYPTO_EXAMPLE
 #endif // ECTF_CRYPTO_H