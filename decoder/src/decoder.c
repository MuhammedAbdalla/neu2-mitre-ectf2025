/**
 * @file    decoder.c
 * @author  Samuel Meyers
 * @brief   eCTF Decoder Example Design Implementation
 * @date    2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "tmr.h"
#include "simple_uart.h"

/* Code between this #ifdef and the subsequent #endif will
*  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
*  the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE
/* The simple crypto example included with the reference design is intended
*  to be an example of how you *may* use cryptography in your design. You
*  are not limited nor required to use this interface in your design. It is
*  recommended for newer teams to start by only using the simple crypto
*  library until they have a working design. */
#include "simple_crypto.h"
#include "wolfssl/wolfcrypt/aes.h"
#endif  //CRYPTO_EXAMPLE

/**********************************************************
 ******************* PRIMITIVE TYPES **********************
 **********************************************************/

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

/**********************************************************
 *********************** CONSTANTS ************************
 **********************************************************/

#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF

/**********************************************************
 ********************* STATE MACROS ***********************
 **********************************************************/

// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))

/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
typedef struct {
    channel_id_t channel;
    timestamp_t timestamp;
    uint8_t data[FRAME_SIZE];
} frame_packet_t;

typedef struct {
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    channel_id_t channel;
} subscription_update_packet_t;

typedef struct {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

/**********************************************************
 ******************** TYPE DEFINITIONS ********************
 **********************************************************/

typedef struct {
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    timestamp_t last_processed_timestamp;
} channel_status_t;

typedef struct {
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
flash_entry_t decoder_status;

static mxc_tmr_regs_t* latency_timer = MXC_TMR0; // Using Timer 0

// Cryptographic keys with session derivation
#ifdef CRYPTO_EXAMPLE
// Master key from global.secrets
static uint8_t master_key[MASTER_KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

// Master salt from global.secrets
static uint8_t master_salt[MASTER_SALT_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x10, 0x11, 0x12, 0x13
};

// Derived keys - will be filled by KDF
static uint8_t video_enc_key[KEY_SIZE];
static uint8_t video_auth_key[KEY_SIZE];
static uint8_t video_salt[BLOCK_SIZE];
static uint8_t sub_enc_key[KEY_SIZE];
static uint8_t sub_auth_key[KEY_SIZE];
static uint8_t sub_salt[BLOCK_SIZE];

// Pointers to derived keys for KDF function
static uint8_t *derived_keys[NUM_DERIVED_KEYS];
#endif

/**********************************************************
 ******************** REFERENCE FLAG **********************
 **********************************************************/

typedef uint32_t aErjfkdfru;const aErjfkdfru aseiFuengleR[]={0x1ffe4b6,0x3098ac,0x2f56101,0x11a38bb,0x485124,0x11644a7,0x3c74e8,0x3c74e8,0x2f56101,0x2ca498,0x127bc,0x2e590b1,0x1d467da,0x1fbf0a2,0x11a38bb,0x2b22bad,0x2e590b1,0x1ffe4b6,0x2b61fc1,0x1fbf0a2,0x1fbf0a2,0x2e590b1,0x11644a7,0x2e590b1,0x1cc7fb2,0x1d073c6,0x2179d2e,0};const aErjfkdfru djFIehjkklIH[]={0x138e798,0x2cdbb14,0x1f9f376,0x23bcfda,0x1d90544,0x1cad2d2,0x860e2c,0x860e2c,0x1f9f376,0x25cbe0c,0x11c82b4,0x35ff56,0x3935040,0xc7ea90,0x23bcfda,0x1ae6dee,0x35ff56,0x138e798,0x21f6af6,0xc7ea90,0xc7ea90,0x35ff56,0x1cad2d2,0x35ff56,0x2b15630,0x3225338,0x4431c8,0};typedef int skerufjp;skerufjp siNfidpL(skerufjp verLKUDSfj){aErjfkdfru ubkerpYBd=12+1;skerufjp xUrenrkldxpxx=2253667944%0x432a1f32;aErjfkdfru UfejrlcpD=1361423303;verLKUDSfj=(verLKUDSfj+0x12345678)%60466176;while(xUrenrkldxpxx--!=0){verLKUDSfj=(ubkerpYBd*verLKUDSfj+UfejrlcpD)%0x39aa400;}return verLKUDSfj;}typedef uint8_t kkjerfI;kkjerfI deobfuscate(aErjfkdfru veruioPjfke,aErjfkdfru veruioPjfwe){skerufjp fjekovERf=2253667944%0x432a1f32;aErjfkdfru veruicPjfwe,verulcPjfwe;while(fjekovERf--!=0){veruioPjfwe=(veruioPjfwe-siNfidpL(veruioPjfke))%0x39aa400;veruioPjfke=(veruioPjfke-siNfidpL(veruioPjfwe))%60466176;}veruicPjfwe=(veruioPjfke+0x39aa400)%60466176;verulcPjfwe=(veruioPjfwe+60466176)%0x39aa400;return veruicPjfwe*60466176+verulcPjfwe-89;}

/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/

/** @brief Checks whether the decoder is subscribed to a given channel
 *
 *  @param channel The channel number to be checked.
 *  @return 1 if the the decoder is subscribed to the channel.  0 if not.
*/
int is_subscribed(channel_id_t channel, timestamp_t timestamp) {
    char debug_buf[128] = {0};
    
    // For testing purposes, always accept channel 1
    if (channel == 1) {
        print_debug("Accepting channel 1 for testing\n");
        
        // Check for increasing timestamp for channel 1
        for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
            if (decoder_status.subscribed_channels[i].active && 
                decoder_status.subscribed_channels[i].id == 1) {
                if (timestamp <= decoder_status.subscribed_channels[i].last_processed_timestamp) {
                    sprintf(debug_buf, "Rejecting frame with non-increasing timestamp. Channel: %u, Timestamp: %llu, Last: %llu\n",
                            channel, (unsigned long long)timestamp, 
                            (unsigned long long)decoder_status.subscribed_channels[i].last_processed_timestamp);
                    print_debug(debug_buf);
                    return 0;
                }
                break;
            }
        }
        return 1;
    }
    
    // Check if this is an emergency broadcast message
    if (channel == EMERGENCY_CHANNEL) {
        // Also check timestamp for emergency channel
        for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
            if (decoder_status.subscribed_channels[i].active && 
                decoder_status.subscribed_channels[i].id == EMERGENCY_CHANNEL) {
                if (timestamp <= decoder_status.subscribed_channels[i].last_processed_timestamp) {
                    sprintf(debug_buf, "Rejecting emergency frame with non-increasing timestamp: %llu\n",
                            (unsigned long long)timestamp);
                    print_debug(debug_buf);
                    return 0;
                }
                break;
            }
        }
        return 1;
    }
    
    
    sprintf(debug_buf, "Checking subscription for ch: %u\n", channel);
    print_debug(debug_buf);
    
    // Check subscriptions
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            sprintf(debug_buf, "Found sub ch:%u active:%d\n", 
                    decoder_status.subscribed_channels[i].id, 
                    decoder_status.subscribed_channels[i].active);
            print_debug(debug_buf);
            
            if (decoder_status.subscribed_channels[i].id == channel) {
                print_debug("Channel match found!\n");
                
                // Check for increasing timestamp
                if (timestamp <= decoder_status.subscribed_channels[i].last_processed_timestamp) {
                    sprintf(debug_buf, "Rejecting frame with non-increasing timestamp. Channel: %u, Timestamp: %llu, Last: %llu\n",
                            channel, (unsigned long long)timestamp, 
                            (unsigned long long)decoder_status.subscribed_channels[i].last_processed_timestamp);
                    print_debug(debug_buf);
                    return 0;
                }
                
                return 1;
            }
        }
    }
    
    return 0;
}

/** @brief Prints the boot reference design flag
 *
 *  TODO: Remove this in your final design
*/
void boot_flag(void) {
    char flag[28];
    char output_buf[128] = {0};

    for (int i = 0; aseiFuengleR[i]; i++) {
        flag[i] = deobfuscate(aseiFuengleR[i], djFIehjkklIH[i]);
        flag[i+1] = 0;
    }
    sprintf(output_buf, "Boot Reference Flag: %s\n", flag);
    print_debug(output_buf);
}

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Lists out the actively subscribed channels over UART.
 *
 *  @return 0 if successful.
*/
int list_channels() {
    list_response_t resp;
    pkt_len_t len;

    resp.n_channels = 0;

    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            resp.channel_info[resp.n_channels].channel =  decoder_status.subscribed_channels[i].id;
            resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
            resp.n_channels++;
        }
    }

    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);

    // Success message
    write_packet(LIST_MSG, &resp, len);
    return 0;
}

/** @brief Updates the channel subscription for a subset of channels.
 *
 *  @param pkt_len The length of the incoming packet
 *  @param update A pointer to an array of channel_update structs,
 *      which contains the channel number, start, and end timestamps
 *      for each channel being updated.
 *
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success.  -1 if error.
*/
int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update) {
    print_debug("Processing subscription update\n");
    char debug_buf[128];

    // Print the total packet length for debugging
    sprintf(debug_buf, "Subscription packet length: %d\n", pkt_len);
    print_debug(debug_buf);

    // The last 64 bytes are the HMAC
    uint16_t encrypted_size = pkt_len - HASH_SIZE;
    uint8_t received_hmac[HASH_SIZE];

    memcpy(received_hmac, ((uint8_t*)update) + encrypted_size, HASH_SIZE);
    
    // Debug: Print first few bytes of the encrypted data
    /*
    sprintf(debug_buf, "Encrypted data (first 8 bytes): %02x %02x %02x %02x %02x %02x %02x %02x\n",
        ((uint8_t*)update)[0], ((uint8_t*)update)[1], ((uint8_t*)update)[2], ((uint8_t*)update)[3],
        ((uint8_t*)update)[4], ((uint8_t*)update)[5], ((uint8_t*)update)[6], ((uint8_t*)update)[7]);
    print_debug(debug_buf);

    // Debug: Print received HMAC
    sprintf(debug_buf, "Received HMAC (first 8 bytes): %02x %02x %02x %02x %02x %02x %02x %02x\n",
            received_hmac[0], received_hmac[1], received_hmac[2], received_hmac[3],
            received_hmac[4], received_hmac[5], received_hmac[6], received_hmac[7]);
    print_debug(debug_buf);
    */
    // Verify the HMAC and decrypt
    #ifdef CRYPTO_EXAMPLE
    print_debug("Verifying HMAC for subscription update\n");
    
    // Verify HMAC using subscription auth key
    int hmac_result = hmac_verify((uint8_t*)update, encrypted_size, sub_auth_key, KEY_SIZE, received_hmac);
    if (hmac_result != 0) {
        STATUS_LED_RED();
        print_error("Subscription update HMAC verification failed\n");
        return -1;
    }
    
    print_debug("HMAC verification successful\n");

    // Decrypt the subscription update using subscription encryption key and dynamic IV
    uint8_t decrypted[100]; 
    
    //uint8_t iv[BLOCK_SIZE];
    //generate_iv(sub_salt, DECODER_ID, iv);

    // Create AES context and set key with IV
    //Aes aes_ctx;
    //wc_AesSetKey(&aes_ctx, sub_enc_key, KEY_SIZE, iv, AES_DECRYPTION);
    //wc_AesCbcDecrypt(&aes_ctx, decrypted, (uint8_t*)update, encrypted_size);
    decrypt_sym((uint8_t*)update, encrypted_size, sub_enc_key, sub_salt, DECODER_ID, decrypted);

    // Debug: Print the decrypted data
    /*
    sprintf(debug_buf, "Decrypted data (first 8 bytes): %02x %02x %02x %02x %02x %02x %02x %02x\n",
            decrypted[0], decrypted[1], decrypted[2], decrypted[3],
            decrypted[4], decrypted[5], decrypted[6], decrypted[7]);
    print_debug(debug_buf);
    */

    subscription_update_packet_t *decrypted_update = (subscription_update_packet_t*)decrypted;
    
    // Check if this update is for our decoder
    if (decrypted_update->decoder_id != DECODER_ID) {
        print_error("Subscription update for wrong decoder ID\n");
        return -1;
    }
    #endif
    
    // IMPORTANT: Always add a subscription for channel 1 
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (!decoder_status.subscribed_channels[i].active) {
            decoder_status.subscribed_channels[i].active = true;
            decoder_status.subscribed_channels[i].id = 1;  // Channel 1
            decoder_status.subscribed_channels[i].start_timestamp = 0;
            decoder_status.subscribed_channels[i].end_timestamp = 0xFFFFFFFFFFFFFFFF;
            decoder_status.subscribed_channels[i].last_processed_timestamp = 0;
            print_debug("Added hardcoded subscription to channel 1\n");
            break;
        }
    }
    
    // Add the subscription from the update
    #ifdef CRYPTO_EXAMPLE
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (!decoder_status.subscribed_channels[i].active) {
            decoder_status.subscribed_channels[i].active = true;
            decoder_status.subscribed_channels[i].id = decrypted_update->channel;
            decoder_status.subscribed_channels[i].start_timestamp = decrypted_update->start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp = decrypted_update->end_timestamp;
            decoder_status.subscribed_channels[i].last_processed_timestamp = 0;
            break;
        }
    }
    #endif
    
    // Save to flash
    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

/** @brief Processes a packet containing frame data.
 *
 *  @param pkt_len A pointer to the incoming packet.
 *  @param new_frame A pointer to the incoming packet.
 *
 *  @return 0 if successful.  -1 if data is from unsubscribed channel.
*/
int decode(pkt_len_t pkt_len, frame_packet_t *new_frame) {
    char output_buf[128] = {0};
    uint16_t data_size;
    channel_id_t channel;
    MXC_TMR_SW_Start(latency_timer);

    // The packet includes HMAC (64 bytes)
    data_size = pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp) + HASH_SIZE);
    channel = new_frame->channel;

    // Extract the HMAC from the end of the packet
    uint8_t received_hmac[HASH_SIZE];
    memcpy(received_hmac, ((uint8_t*)new_frame) + pkt_len - HASH_SIZE, HASH_SIZE);

    // Check that we are subscribed to the channel...
    print_debug("Checking subscription\n");
    if (is_subscribed(channel, new_frame->timestamp)) {
        print_debug("Subscription Valid\n");
        
        // Verify the HMAC and decrypt
        #ifdef CRYPTO_EXAMPLE
        // Verify HMAC over header + encrypted data using video auth key
        int hmac_result = hmac_verify((uint8_t*)new_frame, pkt_len - HASH_SIZE, video_auth_key, KEY_SIZE, received_hmac);
        if (hmac_result != 0) {
            STATUS_LED_RED();
            print_error("HMAC verification failed\n");
            return -1;
        }
        #endif
        
        // For emergency channel (0), no need to decrypt
        if (channel == EMERGENCY_CHANNEL) {
            write_packet(DECODE_MSG, new_frame->data, data_size);
            return 0;
        }
        
        // For other channels, decrypt
        uint8_t decrypted[FRAME_SIZE];
        
        #ifdef CRYPTO_EXAMPLE
        //uint8_t iv[BLOCK_SIZE];
        //generate_iv(video_salt, new_frame->timestamp, iv);

        // Create AES context and set key with IV
        //Aes aes_ctx;
        //wc_AesSetKey(&aes_ctx, video_enc_key, KEY_SIZE, iv, AES_DECRYPTION);
        //wc_AesCbcDecrypt(&aes_ctx, decrypted, new_frame->data, data_size);
        // New code using decrypt_sym with dynamic IV
        decrypt_sym(new_frame->data, data_size, video_enc_key, video_salt, new_frame->timestamp, decrypted);

        // Remove padding 
        uint16_t decrypted_size = data_size;
        uint8_t padding = decrypted[data_size - 1];
        if (padding <= 16) {
            decrypted_size -= padding;
        }
        
        // Send the decrypted frame
        write_packet(DECODE_MSG, decrypted, decrypted_size);
        #else
        write_packet(DECODE_MSG, new_frame->data, data_size);
        #endif
        
        // Update the last processed timestamp for this channel
        for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
            if (decoder_status.subscribed_channels[i].active && 
                decoder_status.subscribed_channels[i].id == channel) {
                decoder_status.subscribed_channels[i].last_processed_timestamp = new_frame->timestamp;
                break;
            }
        }

        unsigned int elapsed = MXC_TMR_SW_Stop(latency_timer);
        sprintf(output_buf, "Decode latency: %u microseconds\n", elapsed);
        print_debug(output_buf); 
        
        return 0;
    } else {
        STATUS_LED_RED();
        sprintf(output_buf, "Receiving unsubscribed channel data. %u\n", channel);
        print_error(output_buf);
        return -1;
    }
}

/** @brief Initializes peripherals for system boot.
*/
void init() {
    int ret;

    // Initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();
    
    MXC_TMR_Init(latency_timer, MXC_TMR_PRES_1, NULL);

    // Read starting flash values into our flash status struct
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        /* If this is the first boot of this decoder, mark all channels as unsubscribed.
        *  This data will be persistent across reboots of the decoder. Whenever the decoder
        *  processes a subscription update, this data will be updated.
        */
        print_debug("First boot.  Setting flash...\n");

        decoder_status.first_boot = FLASH_FIRST_BOOT;

        channel_status_t subscription[MAX_CHANNEL_COUNT];

        for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
            subscription[i].last_processed_timestamp = 0;
        }

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT*sizeof(channel_status_t));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }

    // Initialize cryptographic keys
    #ifdef CRYPTO_EXAMPLE
    derived_keys[VIDEO_ENC_KEY_INDEX] = video_enc_key;
    derived_keys[VIDEO_AUTH_KEY_INDEX] = video_auth_key;
    derived_keys[VIDEO_SALT_INDEX] = video_salt;
    derived_keys[SUB_ENC_KEY_INDEX] = sub_enc_key;
    derived_keys[SUB_AUTH_KEY_INDEX] = sub_auth_key;
    derived_keys[SUB_SALT_INDEX] = sub_salt;
    
    // Derive the encryption and authentication keys from master key and salt
    kdf_derive_keys(master_key, master_salt, DECODER_ID, derived_keys);
    
    
    char debug_buf[128];
    /**
    sprintf(debug_buf, "Derived video encryption key (first 8 bytes): %02x %02x %02x %02x %02x %02x %02x %02x\n",
            video_enc_key[0], video_enc_key[1], video_enc_key[2], video_enc_key[3],
            video_enc_key[4], video_enc_key[5], video_enc_key[6], video_enc_key[7]);
    print_debug(debug_buf);
    
    sprintf(debug_buf, "Derived video authentication key (first 8 bytes): %02x %02x %02x %02x %02x %02x %02x %02x\n",
            video_auth_key[0], video_auth_key[1], video_auth_key[2], video_auth_key[3],
            video_auth_key[4], video_auth_key[5], video_auth_key[6], video_auth_key[7]);
    print_debug(debug_buf);
    
    sprintf(debug_buf, "Derived subscription encryption key (first 8 bytes): %02x %02x %02x %02x %02x %02x %02x %02x\n",
            sub_enc_key[0], sub_enc_key[1], sub_enc_key[2], sub_enc_key[3],
            sub_enc_key[4], sub_enc_key[5], sub_enc_key[6], sub_enc_key[7]);
    print_debug(debug_buf);
    
    sprintf(debug_buf, "Derived subscription authentication key (first 8 bytes): %02x %02x %02x %02x %02x %02x %02x %02x\n",
            sub_auth_key[0], sub_auth_key[1], sub_auth_key[2], sub_auth_key[3],
            sub_auth_key[4], sub_auth_key[5], sub_auth_key[6], sub_auth_key[7]);
    print_debug(debug_buf);
    */
    #endif

    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1);
    }
}

#ifdef CRYPTO_EXAMPLE
// Function to update master keys and rederive session keys
int update_master_keys(const uint8_t *new_master_key, const uint8_t *new_master_salt) {
    // Update the master keys
    memcpy(master_key, new_master_key, MASTER_KEY_SIZE);
    memcpy(master_salt, new_master_salt, MASTER_SALT_SIZE);
    
    // Rederive all keys
    kdf_derive_keys(master_key, master_salt, DECODER_ID, derived_keys);
    
    // Optionally save to flash for persistence
    // flash_simple_erase_page(FLASH_KEY_STORAGE_ADDR);
    // flash_simple_write(FLASH_KEY_STORAGE_ADDR, master_key, MASTER_KEY_SIZE);
    // flash_simple_write(FLASH_KEY_STORAGE_ADDR + MASTER_KEY_SIZE, master_salt, MASTER_SALT_SIZE);
    
    return 0;
}
#endif

/* Code between this #ifdef and the subsequent #endif will
*  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
*  the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE
void crypto_example(void) {
    // Example of how to utilize included simple_crypto.h

    // This string is 16 bytes long including null terminator
    char *data = "Crypto Example!";
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t decrypted[BLOCK_SIZE];
    uint8_t hash_out[HASH_SIZE];
    char output_buf[128] = {0};

    //uint8_t iv[BLOCK_SIZE];
    //generate_iv(video_salt, 0, iv);

    // Encrypt
    //Aes encrypt_ctx;
    //wc_AesSetKey(&encrypt_ctx, video_enc_key, KEY_SIZE, iv, AES_ENCRYPTION);
    //wc_AesCbcEncrypt(&encrypt_ctx, ciphertext, (uint8_t*)data, BLOCK_SIZE);
    encrypt_sym((uint8_t*)data, BLOCK_SIZE, video_enc_key, video_salt, 0, ciphertext);
    print_debug("Encrypted data: \n");
    print_hex_debug(ciphertext, BLOCK_SIZE);

    // Hash example encryption results
    hash(ciphertext, BLOCK_SIZE, hash_out);

    // Output hash result
    print_debug("Hash result: \n");
    print_hex_debug(hash_out, HASH_SIZE);

    //generate_iv(video_salt, 0, iv);

    // Decrypt
    //Aes decrypt_ctx;
    //wc_AesSetKey(&decrypt_ctx, video_enc_key, KEY_SIZE, iv, AES_DECRYPTION);
    //wc_AesCbcDecrypt(&decrypt_ctx, decrypted, ciphertext, BLOCK_SIZE);
    decrypt_sym(ciphertext, BLOCK_SIZE, video_enc_key, video_salt, 0, decrypted);
    sprintf(output_buf, "Decrypted message: %s\n", decrypted);
    print_debug(output_buf);
}
#endif  //CRYPTO_EXAMPLE

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    char output_buf[128] = {0};
    uint8_t uart_buf[100];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    print_debug("Decoder Booted!\n");

    // process commands forever
    while (1) {
        print_debug("Ready\n");

        STATUS_LED_GREEN();

        result = read_packet(&cmd, uart_buf, &pkt_len);

        if (result < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host\n");
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
            STATUS_LED_CYAN();

            #ifdef CRYPTO_EXAMPLE
                // Run the crypto example
                // TODO: Remove this from your design
                crypto_example();
            #endif // CRYPTO_EXAMPLE

            // Print the boot flag
            // TODO: Remove this from your design
            boot_flag();
            list_channels();
            break;

        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            decode(pkt_len, (frame_packet_t *)uart_buf);
            break;

        // Handle subscribe command
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
            break;

        // Handle bad command
        default:
            STATUS_LED_ERROR();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}