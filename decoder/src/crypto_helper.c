#include <stdint.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha512.h>

#include "crypto_helper.h"

#include "host_messaging.h"

uint8_t kve[KEY_SIZE];
uint8_t kse[KEY_SIZE];
uint8_t kfe[KEY_SIZE];
uint8_t kva[KEY_SIZE];
uint8_t ksa[KEY_SIZE];
uint8_t kfa[KEY_SIZE];

extern channel_id_t channel_list[MAX_CHANNEL_COUNT];

void hex_dump(uint8_t* data, size_t len, char* tmp)
{
	sprintf(tmp, "%d) ", len);

	for (size_t i = 0; i < len; i++)
	{
		if (i)
		{
			strcat(tmp, ",");
		}

		char aux[0x10];
		sprintf(aux, "%02X", data[i]);
		strcat(tmp, aux);
	}
}

uint8_t* rle_decode(const uint8_t* encoded_data, size_t encoded_len, size_t* decoded_len)
{
    if (encoded_data == NULL || encoded_len == 0 || encoded_len % 2 != 0) {
        *decoded_len = 0;
        return NULL;
    }

    size_t decoded_size = encoded_data[0] | (encoded_data[1] << 8);

    static uint8_t decoded_data[0x1000];

    size_t decoded_index = 0;
    for (size_t i = 2; i < encoded_len; i += 2) {
        uint8_t count = encoded_data[i];
        uint8_t value = encoded_data[i + 1];
        for (uint8_t j = 0; j < count; ++j) {
            decoded_data[decoded_index++] = value;
        }
    }

    *decoded_len = decoded_size;
    return decoded_data;
}

int decrypt_cbc_aes256(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext, uint8_t *iv)
{
    Aes ctx;
    int result;

    result = wc_AesSetKey(&ctx, key, KEY_SIZE, iv, AES_DECRYPTION);
    if (result != 0)
    {
        return -1;
    }

    result = wc_AesCbcDecrypt(&ctx, plaintext, ciphertext, len);
    if (result != 0)
    {
    	return result;
    }

    return 0;
}

int encrypt_cbc_aes256(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext, uint8_t *iv)
{
    Aes ctx;
    int result;

    result = wc_AesSetKey(&ctx, key, KEY_SIZE, iv, AES_ENCRYPTION); 
    if (result != 0) 
    {
        return -1; 
    }

    result = wc_AesCbcEncrypt(&ctx, ciphertext, plaintext, len);
    if (result != 0) 
    {
        return result;
    }

    return 0;
}

int verify_hmac_sha256(uint8_t *hmac, uint8_t *key, uint8_t *message, size_t message_len, bool compute)
{
    int ret;
    Hmac hmac_ctx;
    uint8_t computed_hmac[SHA256_DIGEST_SIZE];

    wc_HmacInit(&hmac_ctx, NULL, INVALID_DEVID);

    ret = wc_HmacSetKey(&hmac_ctx, WC_SHA256, key, KEY_SIZE);
    if (ret != 0)
    {
        return -1;
    }

    ret = wc_HmacUpdate(&hmac_ctx, message, message_len);
    if (ret != 0)
    {
        return -1;
    }

    ret = wc_HmacFinal(&hmac_ctx, computed_hmac);
    if (ret != 0)
    {
        return -1;
    }

    wc_HmacFree(&hmac_ctx);

    if (compute)
    {
	    memcpy(hmac, computed_hmac, SHA256_DIGEST_SIZE);

	    return 0;
    }
    else
    {
    	return memcmp(hmac, computed_hmac, SHA256_DIGEST_SIZE);
    }
}

void generate_secrets(char *sec)
{
#define CHANNELS "+c+: ["

	memset(&channel_list, 0, sizeof(channel_list));

	char* tmp = strstr(sec, CHANNELS);

	size_t i = 0;

	if (tmp)
	{
		tmp += strlen(CHANNELS);

		while (tmp)
		{
			char* aux = strstr(tmp, ",");

			if (aux)
			{
				size_t len = aux - tmp;

				if (len < 0x10)
				{
					char aux[0x10];
					strncpy(aux, tmp, len);
					aux[len] = 0;

					if (i < MAX_CHANNEL_COUNT)
					{
						channel_list[i++] = atoi(aux);
					}
				}

				tmp = aux + 1;
			}
			else
			{
				aux = strstr(tmp, "]");

				if (aux)
				{
					size_t len = aux - tmp;

					if (len < 0x10)
					{
						char aux[0x10];
						strncpy(aux, tmp, len);
						aux[len] = 0;

						if (i < MAX_CHANNEL_COUNT)
						{
							channel_list[i++] = atoi(aux);
						}
					}
				}

				break;
				
			}
		}
	}

#if 1 
	for (int i = 0; i < MAX_CHANNEL_COUNT; i++)
	{
		if (channel_list[i])
		{
			char aux[0x100];
			sprintf(aux, "CHANNEL %d", channel_list[i]);
			print_debug(aux);
		}
	}
#endif

#define SECRET_STR "+s+: +"

	char secret[0x100];
	
	memset(&secret, 0, sizeof(secret));

	tmp = strstr(sec, SECRET_STR);

	if (tmp)
	{
		tmp += strlen(SECRET_STR);

		char* aux = strstr(tmp, "+");

		if (aux)
		{
			size_t len = aux - tmp;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"

			if (len < sizeof(secret))
			{
				strncpy(secret, tmp, len);
			}

#pragma GCC diagnostic pop
		}
	}

#if 0
	char aux[0x500];
	sprintf(aux, "SECRET [%s]", secret);
	print_debug(aux);
#endif

	verify_hmac_sha256(kve, (uint8_t*)secret, (uint8_t*)secret, strlen(secret), true);
	verify_hmac_sha256(kse, (uint8_t*)secret+5, (uint8_t*)secret, strlen(secret), true);
	verify_hmac_sha256(kfe, (uint8_t*)secret+10, (uint8_t*)secret, strlen(secret), true);
	verify_hmac_sha256(kva, (uint8_t*)secret+15, (uint8_t*)secret, strlen(secret), true);
	verify_hmac_sha256(ksa, (uint8_t*)secret+20, (uint8_t*)secret, strlen(secret), true);
	verify_hmac_sha256(kfa, (uint8_t*)secret+25, (uint8_t*)secret, strlen(secret), true);

#if 0
	hex_dump(secret, strlen(secret), aux);
	print_debug(aux);
	
	hex_dump(kve, KEY_SIZE, aux);
	print_debug(aux);
	hex_dump(kse, KEY_SIZE, aux);
	print_debug(aux);
	hex_dump(kfe, KEY_SIZE, aux);
	print_debug(aux);

	hex_dump(kva, KEY_SIZE, aux);
	print_debug(aux);
	hex_dump(ksa, KEY_SIZE, aux);
	print_debug(aux);
	hex_dump(kfa, KEY_SIZE, aux);
	print_debug(aux);
#endif
}
