//
// Created by clemens on 01.10.24.
//

#include "globals.h"
#include "hal.h"

// This mutex will be locked by the reboot task as well as by the flash task
// This prevents the device from rebooting while flashing
mutex_t reboot_mutex;

struct board_info board_info = {0};
struct carrier_board_info carrier_board_info = {0};

EVENTSOURCE_DECL(netif_events);

void InitGlobals() {
  chMtxObjectInit(&reboot_mutex);

  // A transient ID read failure must not select the wrong Ethernet PHY.
  // Keep retrying with bus recovery; never turn "N/A" into a hardware choice.
  while (!ID_EEPROM_GetBoardInfo(&board_info)) {
    palToggleLine(LINE_HEARTBEAT_LED_RED);
    chThdSleepMilliseconds(250);
  }
  palSetLine(LINE_HEARTBEAT_LED_RED);
  ID_EEPROM_GetCarrierBoardInfo(&carrier_board_info);
}
