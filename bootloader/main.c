// clang-format off
#include "ch.h"
#include "hal.h"
// clang-format on

#include <board_ex.h>
#include <board_variant.h>
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

/*
 * Clears the reset cause flags and reboots into the application image.
 *
 * RMVF is written here so that the reset we trigger is seen as a plain warm
 * reset by the next bootloader start. Without it, a POR flag left over from the
 * last power-on would make every later warm reset look like a power-on, which
 * would disable the bootloader window for the flashing tools.
 */
static void reset_into_application(void) {
  RTC->BKP0R = 0xB0043D;
  WRITE_REG(RCC->RSR, RCC_RSR_RMVF);
  MODIFY_REG(SYSCFG->UR2, SYSCFG_UR2_BOOT_ADD0,
             (BOOT_ADDRESS >> 16) << SYSCFG_UR2_BOOT_ADD0_Pos);
  NVIC_SystemReset();
  while (1);
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
    reset_into_application();
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
    reset_into_application();
  } else {
    return;
  }

#else
  // We don't have EEPROM, so we cannot verify the image, just jump to it.
  reset_into_application();
#endif
}

/*
 * Application entry point.
 */
int main(void) {
  /*
   * Read the reset cause before anything can clear it (PhyGsw141_Reset() writes
   * RMVF). A real power-on resets RCC->RSR in hardware, while the backup domain
   * (RTC->BKP0R) already survives below ~1.2 V. On a board that is
   * parasitically powered through its I2C pull-ups while switched off (e.g. a
   * BMS holding SDA/SCL at ~1 V pulls 3V3 up to ~0.55 V), BKP0R keeps its magic
   * across a power cycle even though the MCU saw a proper POR - the bootloader
   * then ran through DHCP plus its 5/30 s window on every cold start.
   */
  const uint32_t reset_flags = RCC->RSR;
  const bool was_power_on_reset = (reset_flags & RCC_RSR_PORRSTF) != 0;

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

  // InitGlobals() just read board_info from the ID EEPROM, so the board can
  // now be identified. This applies everything that differs between the board
  // variants -- currently the Ethernet PHY, which halInit() could only skip
  // over above (see board_variant.h).
  InitBoardVariant(board_info.board_id, sizeof(board_info.board_id));

  InitHeartbeat();
  InitStatusLed();

  bool is_developer_mode = false;
#if defined(BOARD_HAS_EEPROM)

  // Check, if we have a valid image
  struct bootloader_info info = {0};
  if (ID_EEPROM_GetBootloaderInfo(&info) && info.developer_mode == 1) {
    is_developer_mode = true;
  }
#endif

  // True, when the board was started via power up. If we have a valid image
  // (and no developer mode), directly jump to it without waiting.
  //
  // This used to be `RTC->BKP0R != 0xB0043D`, which is not reliable: the backup
  // domain outlives the rest of the chip when the board is parasitically
  // powered (see reset_flags above), so a power cycle was mistaken for a warm
  // reset.
  if (was_power_on_reset && !is_developer_mode) {
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
  while (!ID_EEPROM_GetMacAddress(mac_address, sizeof(mac_address))) {
    chThdSleepMilliseconds(250);
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
    if (is_developer_mode) {
      // Developer mode, wait 30 seconds to give the user plenty of time to
      // flash.
      chThdSleep(TIME_S2I(30));
    } else {
      // Normal user mode, 5 seconds is enough
      chThdSleep(TIME_S2I(5));
    }
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
