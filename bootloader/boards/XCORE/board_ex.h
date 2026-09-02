#ifndef BOARD_EX_H
#define BOARD_EX_H

#include "board_phy.h"

// The xcore and xcore-lite boards are identical except for the Ethernet
// PHY (GSW141 vs RTL8201F). BoardPhy_GetAddress()/BoardPhy_Reset() dispatch
// to the correct one at runtime, based on the ID EEPROM's board_id -- see
// board_phy.h for why this has to happen as a second pass, after main()
// re-invokes macInit().
#define BOARD_PHY_ADDRESS BoardPhy_GetAddress()
#define BOARD_PHY_RESET() BoardPhy_Reset()

#define BOARD_HAS_RGB_STATUS 1
#define BOARD_HAS_RGB_HEARTBEAT 1
#define BOARD_STATUS_LED_INVERTED
#define BOARD_HEARTBEAT_LED_INVERTED

#define BOARD_HAS_EEPROM 1
#define EEPROM_DEVICE_ADDRESS 0b1010011
#define CARRIER_EEPROM_DEVICE_ADDRESS 0b1010000

// Define the fallback IP settings for this board (if DHCP fails)
// 10.0.0.254
#define FALLBACK_IP_ADDRESS 0x0A0000FE
// 10.0.0.1
#define FALLBACK_GATEWAY 0x0A000001
// 255.255.255.0
#define FALLBACK_NETMASK 0xFFFFFF00

// Flash information for the bootloader
#define BOOT_ADDRESS 0x8020000
// Available flash pages for user program
#define FLASH_PAGE_COUNT 7
// Size of each flash page in bytes
#define FLASH_PAGE_SIZE_BYTES 0x20000
// Size of flash memory for the user program
#define PROGRAM_FLASH_SIZE_BYTES (FLASH_PAGE_COUNT * FLASH_PAGE_SIZE_BYTES)

#endif