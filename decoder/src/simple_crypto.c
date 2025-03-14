/**
 * @file "simple_crypto.c"
 * @author Ben Janis
 * @brief Simplified Crypto API Implementation
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

 #if CRYPTO_EXAMPLE

 #include "simple_crypto.h"
 #include <stdint.h>
 #include <string.h>
 #include "host_messaging.h"
 
 Hmac hmac;
 
 /******************************** FUNCTION PROTOTYPES ********************************/
 
 /**
  * @brief Derives session keys from a master key and salt
  * 
  * Based on the key derivation function in RFC 3711 (SRTP)
  * 
  * @param master_key The master key (32 bytes)
  * @param master_salt The master salt (14 bytes)
  * @param device_id Device ID to use as context
  * @param derived_keys Array of output buffers for derived keys and salts
  * 
  * @return 0 on success, non-zero on error
  */
 int kdf_derive_keys(const uint8_t *master_key, const uint8_t *master_salt, 
                     uint32_t device_id, uint8_t *derived_keys[NUM_DERIVED_KEYS]) {
     // Labels for deriving different keys (as per RFC 3711)
     const uint8_t video_enc_label[LABEL_SIZE] = "vid enc";
     const uint8_t video_auth_label[LABEL_SIZE] = "vid aut";
     const uint8_t video_salt_label[LABEL_SIZE] = "vid slt";
     const uint8_t sub_enc_label[LABEL_SIZE] = "sub enc";
     const uint8_t sub_auth_label[LABEL_SIZE] = "sub aut";
     const uint8_t sub_salt_label[LABEL_SIZE] = "sub slt";
     
     // Create key context structures with device_id + label
     uint8_t *labels[NUM_DERIVED_KEYS] = {
         (uint8_t*)video_enc_label,
         (uint8_t*)video_auth_label,
         (uint8_t*)video_salt_label,
         (uint8_t*)sub_enc_label,
         (uint8_t*)sub_auth_label,
         (uint8_t*)sub_salt_label
     };
     
     // Copy master key to a non-const buffer for WolfSSL
     uint8_t key_copy[MASTER_KEY_SIZE];
     memcpy(key_copy, master_key, MASTER_KEY_SIZE);
     
     // AES context for PRF
     Aes aes_ctx;
     
     // Derive each key with its own label
     for (int key_idx = 0; key_idx < NUM_DERIVED_KEYS; key_idx++) {
         // Prepare context and salt
         uint8_t context[LABEL_SIZE + sizeof(uint32_t)];
         memcpy(context, &device_id, sizeof(uint32_t));
         memcpy(context + sizeof(uint32_t), labels[key_idx], LABEL_SIZE);
         
         // Create input by XORing salt with context
         uint8_t input[BLOCK_SIZE] = {0};
         for (int i = 0; i < MASTER_SALT_SIZE; i++) {
             input[i] = master_salt[i];
         }
         for (int i = 0; i < sizeof(context); i++) {
             input[i % BLOCK_SIZE] ^= context[i];
         }
         
         // Use empty IV for PRF
         uint8_t iv[BLOCK_SIZE] = {0}; 
         
         // Initialize AES for encryption
         wc_AesSetKey(&aes_ctx, key_copy, MASTER_KEY_SIZE, iv, AES_ENCRYPTION);
         
         // Generate key material (salt keys are BLOCK_SIZE, other keys are KEY_SIZE)
         size_t key_size = (key_idx == VIDEO_SALT_INDEX || key_idx == SUB_SALT_INDEX) 
                          ? BLOCK_SIZE : KEY_SIZE;
         
         // Use AES as a PRF
         for (int i = 0; i < key_size; i += BLOCK_SIZE) {
             wc_AesEncryptDirect(&aes_ctx, derived_keys[key_idx] + i, input);
             
             // Increment counter for next block
             for (int j = BLOCK_SIZE - 1; j >= 0; j--) {
                 if (++input[j] != 0) {
                     break;
                 }
             }
         }
     }
     
     return 0;
 }
 
 /**
  * @brief Generates IV from salt and packet index
  * 
  * @param salt Salt to use as base for IV
  * @param packet_index Index to use for IV (e.g. timestamp or counter)
  * @param iv Output buffer for IV (BLOCK_SIZE bytes)
  * 
  * @return 0 on success
  */
 int generate_iv(const uint8_t *salt, uint32_t packet_index, uint8_t *iv) {
     // Copy salt to IV
     memcpy(iv, salt, BLOCK_SIZE);
     
     // XOR last 4 bytes with packet index
     for (int i = 0; i < sizeof(uint32_t); i++) {
         iv[BLOCK_SIZE - sizeof(uint32_t) + i] ^= 
             (packet_index >> (8 * (sizeof(uint32_t) - i - 1))) & 0xFF;
     }
     
     return 0;
 }
 
 /** @brief Encrypts plaintext using a symmetric cipher
  *
  * @param plaintext A pointer to a buffer of length len containing the
  *         plaintext to encrypt
  * @param len The length of the plaintext to encrypt. Must be a multiple of
  *         BLOCK_SIZE (16 bytes)
  * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
  *         the key to use for encryption
  * @param salt A pointer to the salt used for IV generation (BLOCK_SIZE bytes)
  * @param packet_index Packet sequence number for IV generation
  * @param ciphertext A pointer to a buffer of length len where the resulting
  *         ciphertext will be written to
  *
  * @return 0 on success, -1 on bad length, other non-zero for other error
  */
 int encrypt_sym(const uint8_t *plaintext, size_t len, const uint8_t *key, 
                 const uint8_t *salt, uint32_t packet_index, uint8_t *ciphertext) {
     Aes ctx;
     int result;
     
     // Generate IV using salt and packet index
     uint8_t iv[BLOCK_SIZE];
     result = generate_iv(salt, packet_index, iv);
     if (result != 0)
         return result;
 
     // Ensure valid length
     if (len <= 0 || len % BLOCK_SIZE)
         return -1;
 
     // Copy key to non-const buffer for WolfSSL
     uint8_t key_copy[KEY_SIZE];
     memcpy(key_copy, key, KEY_SIZE);
 
     // Set the key for encryption with IV for CBC mode
     result = wc_AesSetKey(&ctx, key_copy, KEY_SIZE, iv, AES_ENCRYPTION);
     if (result != 0)
         return result;
 
     // Encrypt in CBC mode
     result = wc_AesCbcEncrypt(&ctx, ciphertext, (uint8_t*)plaintext, len);
     if (result != 0)
         return result;
     
     return 0;
 }
 
 /** @brief Decrypts ciphertext using a symmetric cipher
  *
  * @param ciphertext A pointer to a buffer of length len containing the
  *          ciphertext to decrypt
  * @param len The length of the ciphertext to decrypt. Must be a multiple of
  *          BLOCK_SIZE (16 bytes)
  * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
  *          the key to use for decryption
  * @param salt A pointer to the salt used for IV generation (BLOCK_SIZE bytes)
  * @param packet_index Packet sequence number for IV generation
  * @param plaintext A pointer to a buffer of length len where the resulting
  *          plaintext will be written to
  *
  * @return 0 on success, -1 on bad length, other non-zero for other error
  */
 int decrypt_sym(const uint8_t *ciphertext, size_t len, const uint8_t *key, 
                 const uint8_t *salt, uint32_t packet_index, uint8_t *plaintext) {
     Aes ctx;
     int result;
     
     // Generate IV using salt and packet index (must match encryption IV)
     uint8_t iv[BLOCK_SIZE];
     result = generate_iv(salt, packet_index, iv);
     if (result != 0)
         return result;
 
     // Ensure valid length
     if (len <= 0 || len % BLOCK_SIZE)
         return -1;
 
     // Copy key to a non-const buffer
     uint8_t key_copy[KEY_SIZE];
     memcpy(key_copy, key, KEY_SIZE);
 
     // Set the key for decryption with IV for CBC mode
     result = wc_AesSetKey(&ctx, key_copy, KEY_SIZE, iv, AES_DECRYPTION);
     if (result != 0)
         return result;
 
     // Decrypt in CBC mode
     result = wc_AesCbcDecrypt(&ctx, plaintext, (uint8_t*)ciphertext, len);
     if (result != 0)
         return result;
     
     return 0;
 }
 
 /** @brief Hashes arbitrary-length data
  *
  * @param data A pointer to a buffer of length len containing the data
  *         to be hashed
  * @param len The length of the plaintext to hash
  * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
  *         hash output will be written to
  *
  * @return 0 on success, non-zero for other error
  */
 int hash(void *data, size_t len, uint8_t *hash_out) {
     // Pass values to hash
     return wc_Md5Hash((uint8_t *)data, len, hash_out);
 }
 
 /** @brief Generates HMAC for data authentication
  *
  * @param data A pointer to a buffer containing the data to authenticate
  * @param data_len The length of the data to authenticate
  * @param key A pointer to a buffer containing the authentication key
  * @param key_len The length of the authentication key
  * @param hmac_out A pointer to a buffer of length HASH_SIZE where the HMAC will be written
  *
  * @return 0 on success, non-zero for error
  */
 int hmac_authenticate(const uint8_t *data, size_t data_len, const uint8_t *key, 
                      size_t key_len, uint8_t *hmac_out) {
     int ret;
     
     // Initialize HMAC
     ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
     if (ret != 0) return ret;
     
     // Copy to non-const buffer if needed by WolfSSL
     uint8_t key_copy[KEY_SIZE];
     memcpy(key_copy, key, key_len);
     
     ret = wc_HmacSetKey(&hmac, WC_SHA256, key_copy, key_len);
     if (ret != 0) return ret;
     
     ret = wc_HmacUpdate(&hmac, data, data_len);
     if (ret != 0) return ret;
     
     ret = wc_HmacFinal(&hmac, hmac_out);
     if (ret != 0) return ret;
     
     return 0;
 }
 
 /** @brief Verifies HMAC for data authentication
  *
  * @param data A pointer to a buffer containing the data to verify
  * @param data_len The length of the data to verify
  * @param key A pointer to a buffer containing the authentication key
  * @param key_len The length of the authentication key
  * @param hmac A pointer to a buffer of length HASH_SIZE containing the HMAC to verify against
  *
  * @return 0 if HMAC is valid, non-zero otherwise
  */
 int hmac_verify(const uint8_t *data, size_t data_len, const uint8_t *key, 
                size_t key_len, const uint8_t *hmac) {
     uint8_t computed_hmac[HASH_SIZE];
     int ret;
     
     ret = hmac_authenticate(data, data_len, key, key_len, computed_hmac);
     if (ret != 0) return ret;
     
     // Constant-time comparison to prevent timing attacks
     int result = 0;
     for (int i = 0; i < HASH_SIZE; i++) {
         result |= (computed_hmac[i] ^ hmac[i]);
     }
     
     return result; // 0 if HMACs match, non-zero otherwise
 }
 
 #endif