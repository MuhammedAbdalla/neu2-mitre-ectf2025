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
#include "flash_helper.h"
#include "host_messaging.h"
#include "crypto_helper.h"
#include "tmr.h"
#include "secrets/secrets.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/hmac.h"



channel_id_t channel_list[MAX_CHANNEL_COUNT];

flash_entry_t decoder_status;

extern uint8_t kve[KEY_SIZE];
extern uint8_t kse[KEY_SIZE];
extern uint8_t kva[KEY_SIZE];
extern uint8_t ksa[KEY_SIZE];


mxc_tmr_regs_t *latency_timer = MXC_TMR_GET_TMR(0);

/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/

/** @brief Checks whether the decoder is subscribed to a given channel
 *
 *  @param channel The channel number to be checked.
 *  @return 1 if the the decoder is subscribed to the channel.  0 if not.
*/
int is_subscribed(channel_id_t channel) {
    
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active) {
            return 1;
        }
    }
    return 0;
}

void derive_session_key(uint8_t *base_key, uint32_t channel_id, uint8_t *session_key) {
    // Use channel ID instead of timestamp
    verify_hmac_sha256(session_key, base_key, (uint8_t*)&channel_id, sizeof(channel_id), true);
}

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Lists out the actively subscribed channels over UART.
 *
 *  @return 0 if successful.
*/
int list_channels() 
{
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
int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update) 
{
    int i;

    pkt_len -= SHA256_DIGEST_SIZE;

    if (verify_hmac_sha256((uint8_t*)update + pkt_len, ksa, (uint8_t*)update, pkt_len, false) < 0)
    {
        print_error("Failed to authenticate subscription!");
        return -1;
    }

    uint8_t iv[BLOCK_SIZE];
    memcpy(iv, kse, BLOCK_SIZE);

    if (decrypt_cbc_aes256((uint8_t*)update, pkt_len, kse, (uint8_t*)update, iv) < 0)
    {
        print_error("Failed to decrypt subscription!");

        return -1;
    }

    if (update->channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
        return -1;
    }

    if (DECODER_ID != update->decoder_id)
    {
        STATUS_LED_RED();
        //print_error("Failed to update subscription - wrong decoder id\n");
        print_error("Subscription validation failed\n");
        return -1;
    }

    // Check if channel has been configured through secrets    
    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
	    if (channel_list[i] && update->channel == channel_list[i])
	    {
		    break;
	    }
    }

    if (i == MAX_CHANNEL_COUNT) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - channel not allowed\n");
        return -1;
    }

    // Find the first empty slot in the subscription array
    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == update->channel || !decoder_status.subscribed_channels[i].active) {
            decoder_status.subscribed_channels[i].active = true;
            decoder_status.subscribed_channels[i].id = update->channel;
            decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
            break;
        }
    }

    // If we do not have any room for more subscriptions
    if (i == MAX_CHANNEL_COUNT) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - max subscriptions installed\n");
        return -1;
    }

    flash_erase_page(FLASH_STATUS_ADDR);
    flash_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    // Success message with an empty body
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

int decode(pkt_len_t pkt_len, frame_packet_t *new_frame) 
{
    char output_buf[128] = {0};
    uint16_t frame_size;
    channel_id_t channel;

    pkt_len -= SHA256_DIGEST_SIZE;

    if (verify_hmac_sha256((uint8_t*)new_frame + pkt_len, kva, (uint8_t*)new_frame, pkt_len, false) < 0)
    {
        STATUS_LED_RED();
        print_error("Failed to authenticate!");
        return -1;
    }

    frame_size = pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp));

    bool found = false;
    timestamp_t start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
    timestamp_t end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
 
    // First the emergency channel (0) 
    uint32_t emergency_channel = EMERGENCY_CHANNEL; 
    
    uint8_t temp_frame[pkt_len];
    memcpy(temp_frame, new_frame, pkt_len);

    {
        uint8_t iv[BLOCK_SIZE];
        uint8_t iv_salt[8];
        uint8_t channel_hash[SHA256_DIGEST_SIZE];
        Sha256 sha;

        memcpy(iv_salt, kse + (KEY_SIZE - 8), 8);

        wc_InitSha256(&sha);
        wc_Sha256Update(&sha, (uint8_t*)&emergency_channel, sizeof(emergency_channel));
        wc_Sha256Update(&sha, iv_salt, sizeof(iv_salt)); 
        wc_Sha256Final(&sha, channel_hash);

        memcpy(iv, channel_hash, 4);
        memcpy(iv + 4, kve + 4, BLOCK_SIZE - 4);

        uint8_t emergency_kve[KEY_SIZE];
        derive_session_key(kve, emergency_channel, emergency_kve);

        if (decrypt_cbc_aes256(temp_frame, pkt_len, emergency_kve, temp_frame, iv) >= 0)
        {
            frame_packet_t* temp_frame_struct = (frame_packet_t*)temp_frame;
            
            if (temp_frame_struct->channel == EMERGENCY_CHANNEL)
            {
                memcpy(new_frame, temp_frame, pkt_len);
                
                found = true;
                channel = EMERGENCY_CHANNEL;
                start_timestamp = 0;
                end_timestamp = UINT64_MAX;
            }
        }
    }

    if (!found)
    {
        for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++)
        {
            if (decoder_status.subscribed_channels[i].active) 
            {
                uint32_t channel = decoder_status.subscribed_channels[i].id;

                uint8_t iv[BLOCK_SIZE];
                uint8_t iv_salt[8];
                uint8_t channel_hash[SHA256_DIGEST_SIZE];
                Sha256 sha;

                memcpy(iv_salt, kse + (KEY_SIZE - 8), 8);

                wc_InitSha256(&sha);
                wc_Sha256Update(&sha, (uint8_t*)&channel, sizeof(channel));
                wc_Sha256Update(&sha, iv_salt, sizeof(iv_salt)); 
                wc_Sha256Final(&sha, channel_hash);

                memcpy(iv, channel_hash, 4);
                memcpy(iv + 4, kve + 4, BLOCK_SIZE - 4);

                uint8_t session_kve[KEY_SIZE];
                derive_session_key(kve, channel, session_kve);

                uint8_t channel_frame[pkt_len];
                memcpy(channel_frame, new_frame, pkt_len);

                if (decrypt_cbc_aes256(channel_frame, pkt_len, session_kve, channel_frame, iv) >= 0)
                {
                    frame_packet_t* channel_frame_struct = (frame_packet_t*)channel_frame;
                    
                    if (channel == channel_frame_struct->channel)
                    {
                        memcpy(new_frame, channel_frame, pkt_len);
                        
                        start_timestamp = decoder_status.subscribed_channels[i].start_timestamp;
                        end_timestamp = decoder_status.subscribed_channels[i].end_timestamp;

                        found = true;
                        break;
                    }
                }
            }
        }
    }

    if (!found)
    {
        STATUS_LED_RED();
        print_error("Invalid channel id!");
        return -1;
    }
    
    channel = new_frame->channel;

    // The reference design doesn't use the timestamp, but you may want to in your design
    timestamp_t timestamp = new_frame->timestamp;

    if (timestamp < start_timestamp || timestamp > end_timestamp)
    {
        STATUS_LED_RED();
        print_error("Timestamp validation failed");
        return -1;
    }

    static timestamp_t last_timestamp = 0;
    static channel_id_t last_channel = 0xffff;

    if (timestamp <= last_timestamp && last_channel == channel)
    {
        STATUS_LED_RED();
        print_error("Timestamp is not increasing!");
        return -1;
    }

    last_timestamp = timestamp;
    last_channel = channel; 

    // Check that we are subscribed to the channel...
    print_debug("Checking subscription\n");
    if (is_subscribed(channel)) {
        print_debug("Subscription Valid\n");
        /* The reference design doesn't need any extra work to decode, but your design likely will.
        *  Do any extra decoding here before returning the result to the host. */

        size_t len;
        uint8_t* data = rle_decode(new_frame->data, frame_size, &len);
    
        write_packet(DECODE_MSG, data, 64); 
            
        return 0;
    
    } else {
        STATUS_LED_RED();
        sprintf(
            output_buf,
            "Receiving unsubscribed channel data.  %u\n", channel);
        print_error(output_buf);
        return -1;
    }
}

/** @brief Initializes peripherals for system boot.
*/
void init() 
{
    int ret;

    mxc_tmr_cfg_t tmr_cfg;
    tmr_cfg.pres = TMR_PRES_1;
    tmr_cfg.mode = TMR_MODE_CONTINUOUS;
    tmr_cfg.bitMode = TMR_BIT_MODE_32;
    tmr_cfg.clock = MXC_TMR_APB_CLK;
    tmr_cfg.cmp_cnt = 0xFFFFFFFF;
    MXC_TMR_Init(latency_timer, &tmr_cfg, false);

    // Initialize the flash peripheral to enable access to persistent memory
    flash_init();

    // Read starting flash values into our flash status struct
    flash_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
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
        }

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT*sizeof(channel_status_t));

        flash_erase_page(FLASH_STATUS_ADDR);
        flash_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }

    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1);
    }
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) 
{
    char output_buf[128] = {0};
    uint8_t uart_buf[0x2000];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // need to derive keys before accessing flash memory
    generate_secrets(SECRET);

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
