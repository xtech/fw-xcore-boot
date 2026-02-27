// clang-format off
#include "ch.h"
#include "hal.h"
// clang-format on

#include <board_ex.h>
#include <bootloader.h>
#include <globals.h>
#include <heartbeat.h>
#include <id_eeprom.h>
#include <lwip/dhcp.h>
#include <service_discovery.h>
#include <sha256.h>
#include <status_led.h>
#include <string.h>

#include "lwipthread.h"

void link_up(struct netif *netif) {
  if (netif->ip_addr.addr != 0) {
    chEvtBroadcastFlags(&netif_events, NETIF_FLAG_BROADCAST);
  }
}

void jump_to_user_program(void) {
#if defined(BOARD_HAS_EEPROM)

  // Check, if we have a valid image
  struct bootloader_info info = {0};
  if (!ID_EEPROM_GetBootloaderInfo(&info)) {
    // If we don't have a valid image, stay in bootloader and allow bootloading
    // again
    return;
  }

  if (info.developer_mode == 1) {
    // Developer mode, reboot into user program
    RTC->BKP0R = 0xB0043D;
    MODIFY_REG(SYSCFG->UR2, SYSCFG_UR2_BOOT_ADD0,
               (BOOT_ADDRESS >> 16) << SYSCFG_UR2_BOOT_ADD0_Pos);
    NVIC_SystemReset();
    while (1)
      ;
  }

  if (info.image_present != 1) {
    return;
  }

  // Check, if image size is valid
  if (info.image_size > PROGRAM_FLASH_SIZE_BYTES) {
    return;
  }

  // If we have a valid info in our EEPROM, verify the hash before booting
  SHA256_CTX sha256;
  uint8_t validate_hash[32] = {0};
  sha256_init(&sha256);
  sha256_update(&sha256, (uint8_t *)TARGET_FLASH_ADDRESS, info.image_size);
  sha256_final(&sha256, validate_hash);
  if (memcmp(validate_hash, info.image_sha256, sizeof(validate_hash)) == 0) {
    // Program OK, now we can boot to it.
    RTC->BKP0R = 0xB0043D;
    MODIFY_REG(SYSCFG->UR2, SYSCFG_UR2_BOOT_ADD0,
               (BOOT_ADDRESS >> 16) << SYSCFG_UR2_BOOT_ADD0_Pos);
    NVIC_SystemReset();
  } else {
    return;
  }

#else
  // We don't have EEPROM, so we cannot verify the image, just jump to it.
  RTC->BKP0R = 0xB0043D;
  MODIFY_REG(SYSCFG->UR2, SYSCFG_UR2_BOOT_ADD0,
             (BOOT_ADDRESS >> 16) << SYSCFG_UR2_BOOT_ADD0_Pos);
  NVIC_SystemReset();
#endif
}

/*
 * Application entry point.
 */
int main(void) {
  // Need to disable D-Cache for the Ethernet MAC to work properly
  SCB_DisableDCache();
  /*
   * System initializations.
   * - HAL initialization, this also initializes the configured device drivers
   *   and performs the board-specific initializations.
   * - Kernel initialization, the main() function becomes a thread and the
   *   RTOS is active.
   */
  halInit();
  chSysInit();

#if BOARD_HAS_EEPROM
  ID_EEPROM_Init();
#endif

  /*
   * InitGlobals() sets up global variables shared by threads. (e.g. mutex)
   * InitHeartbeat() starts the heartbeat timer to blink an LED as long as the
   * RTOS is running.
   */
  InitGlobals();
  InitHeartbeat();
  InitStatusLed();

  // True, when the board was started via power up. If we have a valid image,
  // directly jump to it without waiting.
  bool is_started_from_power_up = RTC->BKP0R != 0xB0043D;

  if (is_started_from_power_up) {
    SetStatusLedMode(LED_MODE_BLINK_SLOW);
    // No need to actually catch the return value here.
    // If success, we won't return
    // If fail, we bootload as usual.
    jump_to_user_program();
  }

  SetStatusLedMode(LED_MODE_BLINK_FAST);

  /*
   * Setup LWIP stack using the MAC address provided by the EEPROM.
   */
  uint8_t mac_address[6] = {0};
  if (!ID_EEPROM_GetMacAddress(mac_address, sizeof(mac_address))) {
    while (1)
      ;
  }
  lwipthread_opts_t lwipconf_opts = {0};
  lwipconf_opts.addrMode = NET_ADDRESS_DHCP;
  lwipconf_opts.address = 0;
  lwipconf_opts.gateway = 0;
  lwipconf_opts.netmask = 0;
  lwipconf_opts.macaddress = mac_address;
  lwipInit(&lwipconf_opts);
  netif_set_status_callback(netif_default, link_up);

  // Wait for the interface to come up (DHCP)
  event_listener_t event_listener;
  chEvtRegister(&netif_events, &event_listener, 0);
  // Wait for DHCP without a timeout.
  eventmask_t events =
      chEvtWaitAnyTimeout(NETIF_EVENT_ADDRESS_VALID, TIME_INFINITE);
  bool got_address = (events & NETIF_EVENT_ADDRESS_VALID) != 0;
  if (got_address) {
    // Start Service Discovery and Bootloader Thread
    SetStatusLedMode(LED_MODE_BLINK_SLOW);

    // Start the ServiceDiscovery Task.
    InitServiceDiscovery();

    // Start the actual Bootloader Task
    InitBootloaderThread();

    // Timer before starting into user program
#ifndef LINE_PREVENT_BOOT_BUTTON
#if defined(BOARD_HAS_EEPROM)

    // Check, if we have a valid image
    struct bootloader_info info = {0};
    if (ID_EEPROM_GetBootloaderInfo(&info)) {
      if (info.developer_mode == 1) {
        // Developer mode, wait 30 seconds to give the user plenty of time to flash.
        chThdSleep(TIME_S2I(30));
      } else {
        // Normal user mode, 5 seconds is enough
        chThdSleep(TIME_S2I(5));
      }
    } else {
      // We could not fetch bootloader info, wait 30 seconds to give the user plenty of time to flash
      chThdSleep(TIME_S2I(30));
    }

#else
    chThdSleep(TIME_S2I(30));
#endif
#else
    // instead of just sleeping, we can poll a user button to keep device from
    // entering user program
    uint32_t sleep_count = 1000 / 100;
    while (sleep_count-- > 0) {
      chThdSleep(TIME_MS2I(100));
      if (palReadLine(LINE_BUTTON)) {
        // sleep forever, don't boot into user software
        chThdSleep(TIME_INFINITE);
      }
    }
#endif
  } else {
    // Should not be here, reboot and try again
    NVIC_SystemReset();
  }

  while (1) {
    // make sure we're not currently updating the software
    chMtxLock(&reboot_mutex);

    jump_to_user_program();

    // allow bootloader to work again, since jumping to user program didn't work
    chMtxUnlock(&reboot_mutex);
    // Wait a bit
    chThdSleep(TIME_MS2I(100));
  }
}
