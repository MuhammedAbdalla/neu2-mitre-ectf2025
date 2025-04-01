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

#include "secrets/secrets.h"

channel_id_t channel_list[MAX_CHANNEL_COUNT];

flash_entry_t decoder_status;

extern uint8_t kve[KEY_SIZE];
extern uint8_t kse[KEY_SIZE];
extern uint8_t kva[KEY_SIZE];
extern uint8_t ksa[KEY_SIZE];

/**********************************************************
 ******************** REFERENCE FLAG **********************
 **********************************************************/

// trust me, it's easier to get the boot reference flag by
// getting this running than to try to untangle this
// TODO: remove this from your final design
// NOTE: you're not allowed to do this in your code
typedef uint32_t aErjfkdfru;const aErjfkdfru aseiFuengleR[]={0x1ffe4b6,0x3098ac,0x2f56101,0x11a38bb,0x485124,0x11644a7,0x3c74e8,0x3c74e8,0x2f56101,0x2ca498,0x127bc,0x2e590b1,0x1d467da,0x1fbf0a2,0x11a38bb,0x2b22bad,0x2e590b1,0x1ffe4b6,0x2b61fc1,0x1fbf0a2,0x1fbf0a2,0x2e590b1,0x11644a7,0x2e590b1,0x1cc7fb2,0x1d073c6,0x2179d2e,0};const aErjfkdfru djFIehjkklIH[]={0x138e798,0x2cdbb14,0x1f9f376,0x23bcfda,0x1d90544,0x1cad2d2,0x860e2c,0x860e2c,0x1f9f376,0x25cbe0c,0x11c82b4,0x35ff56,0x3935040,0xc7ea90,0x23bcfda,0x1ae6dee,0x35ff56,0x138e798,0x21f6af6,0xc7ea90,0xc7ea90,0x35ff56,0x1cad2d2,0x35ff56,0x2b15630,0x3225338,0x4431c8,0};typedef int skerufjp;skerufjp siNfidpL(skerufjp verLKUDSfj){aErjfkdfru ubkerpYBd=12+1;skerufjp xUrenrkldxpxx=2253667944%0x432a1f32;aErjfkdfru UfejrlcpD=1361423303;verLKUDSfj=(verLKUDSfj+0x12345678)%60466176;while(xUrenrkldxpxx--!=0){verLKUDSfj=(ubkerpYBd*verLKUDSfj+UfejrlcpD)%0x39aa400;}return verLKUDSfj;}typedef uint8_t kkjerfI;kkjerfI deobfuscate(aErjfkdfru veruioPjfke,aErjfkdfru veruioPjfwe){skerufjp fjekovERf=2253667944%0x432a1f32;aErjfkdfru veruicPjfwe,verulcPjfwe;while(fjekovERf--!=0){veruioPjfwe=(veruioPjfwe-siNfidpL(veruioPjfke))%0x39aa400;veruioPjfke=(veruioPjfke-siNfidpL(veruioPjfwe))%60466176;}veruicPjfwe=(veruioPjfke+0x39aa400)%60466176;verulcPjfwe=(veruioPjfwe+60466176)%0x39aa400;return veruicPjfwe*60466176+verulcPjfwe-89;}


/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/

/** @brief Checks whether the decoder is subscribed to a given channel
 *
 *  @param channel The channel number to be checked.
 *  @return 1 if the the decoder is subscribed to the channel.  0 if not.
*/
int is_subscribed(channel_id_t channel) {
    // Check if this is an emergency broadcast message
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    // Check if the decoder has has a subscription
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active) {
            return 1;
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
        print_error("Failed to update subscription - wrong decoder id\n");
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
 
    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++)
    {
        if (decoder_status.subscribed_channels[i].active) 
	{
            uint32_t channel = decoder_status.subscribed_channels[i].id;

            uint8_t iv[BLOCK_SIZE];
            memcpy(iv + 4, kve, BLOCK_SIZE - 4);
	    iv[0] = channel & 0xff;
	    iv[1] = (channel & 0xff00) >> 8;
	    iv[2] = (channel & 0xff0000) >> 16;
	    iv[3] = (channel & 0xff000000) >> 24;

            if (decrypt_cbc_aes256((uint8_t*)new_frame, pkt_len, kve, (uint8_t*)new_frame, iv) < 0)
            {
                STATUS_LED_RED();
                print_error("Failed to decrypt!");
                return -1;
	    }
	    else
	    {
                if (channel == new_frame->channel)
		{
                    start_timestamp = decoder_status.subscribed_channels[i].start_timestamp;
                    end_timestamp = decoder_status.subscribed_channels[i].end_timestamp;

                    found = true;

		    break;
		}
	    }
	}
    }

    char aux2[0x100];
    strcpy(aux2, "PACKET RECEIVED");

    for (size_t k = 0; k < 12; k++)
    {
	    char aux3[0x10];
	    sprintf(aux3, ":%02X", ((uint8_t*)new_frame)[k]);
	    strcat(aux2, aux3);
    }

    print_debug(aux2);

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
        //STATUS_LED_RED();

	char aux[0x100];
	sprintf(aux, "%llu timestamp out of range! [%llu,%llu]", timestamp, start_timestamp, end_timestamp);
        //print_error(aux);
	print_debug(aux);

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

        write_packet(DECODE_MSG, data, len); 
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
