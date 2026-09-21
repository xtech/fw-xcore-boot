//
// Created by clemens on 02.10.24.
//

#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#define TARGET_FLASH_ADDRESS 0x8020000

void InitBootloaderThread(void);

// Validates the image using the normal boot policy and resets into it.
// Returns only if the application cannot be booted. Hold reboot_mutex once the command thread is running.
void jump_to_user_program(void);

#endif  // BOOTLOADER_H
