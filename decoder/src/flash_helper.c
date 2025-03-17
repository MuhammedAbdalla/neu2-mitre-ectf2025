#include "flash_helper.h"

#include "crypto_helper.h"

#include <stdio.h>

#include "flc.h"
#include "icc.h"
#include "nvic_table.h"

#include <stdio.h>

#define STORE_LEN sizeof(flash_entry_t)*2

extern uint8_t kfe[KEY_SIZE];
extern uint8_t kfa[KEY_SIZE];

void flash_irq(void) 
{
    uint32_t temp;
    temp = MXC_FLC0->intr;

    if (temp & MXC_F_FLC_INTR_DONE) {
        MXC_FLC0->intr &= ~MXC_F_FLC_INTR_DONE;
    }

    if (temp & MXC_F_FLC_INTR_AF) {
        MXC_FLC0->intr &= ~MXC_F_FLC_INTR_AF;
        printf(" -> Interrupt! (Flash access failure)\n\n");
    }
}

void flash_init(void) 
{
    // Setup Flash
    MXC_NVIC_SetVector(FLC0_IRQn, flash_irq);
    NVIC_EnableIRQ(FLC0_IRQn);
    MXC_FLC_EnableInt(MXC_F_FLC_INTR_DONEIE | MXC_F_FLC_INTR_AFIE);
    MXC_ICC_Disable(MXC_ICC0);
}

int flash_erase_page(uint32_t address) 
{
    return MXC_FLC_PageErase(address);
}

int flash_read(uint32_t address, void* buffer, uint32_t size) 
{
    uint8_t tmp[STORE_LEN];
    memset(tmp, 0, STORE_LEN);

    uint8_t ke[KEY_SIZE];
    memset(ke, 0, KEY_SIZE);
    ke[0x0] = 1;

    uint8_t iv[BLOCK_SIZE];
    memcpy(iv, kfe, BLOCK_SIZE);

    MXC_FLC_Read(address, (uint32_t *)tmp, STORE_LEN);

    uint8_t ka[KEY_SIZE];
    memset(ka, 0, KEY_SIZE);
    ka[0x0] = 1;

    if (verify_hmac_sha256(tmp + STORE_LEN - SHA256_DIGEST_SIZE, kfa, tmp, STORE_LEN - SHA256_DIGEST_SIZE, false) == 0)
    {
    	decrypt_cbc_aes256(tmp, STORE_LEN - SHA256_DIGEST_SIZE, kfe, buffer, iv);

	return 0;
    }

    return -1;
}

int flash_write(uint32_t address, void* buffer, uint32_t size) 
{
    uint8_t tmp[STORE_LEN];
    memset(tmp, 0, STORE_LEN);

    uint8_t ke[KEY_SIZE];
    memset(ke, 0, KEY_SIZE);
    ke[0x0] = 1;

    uint8_t iv[BLOCK_SIZE];
    memcpy(iv, kfe, BLOCK_SIZE);

    encrypt_cbc_aes256(buffer, size, kfe, tmp, iv);

    uint8_t ka[KEY_SIZE];
    memset(ka, 0, KEY_SIZE);
    ka[0x0] = 1;

    verify_hmac_sha256(tmp + STORE_LEN - SHA256_DIGEST_SIZE, kfa, tmp, STORE_LEN - SHA256_DIGEST_SIZE, true);

    return MXC_FLC_Write(address, STORE_LEN, (uint32_t *)tmp);
}
