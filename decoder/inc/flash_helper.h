#ifndef __FLASH_HELPER__
#define __FLASH_HELPER__

#include "common.h"

#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))

void flash_init(void);

int flash_erase_page(uint32_t address);

int flash_read(uint32_t address, void* buffer, uint32_t size);

int flash_write(uint32_t address, void* buffer, uint32_t size);

#endif
