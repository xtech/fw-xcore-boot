#include "board_phy.h"

#include <string.h>

#include "ch.h"
#include "hal.h"
#include "phy_gsw141.h"
#include "phy_rtl8201f.h"

typedef enum {
  BOARD_VARIANT_NOT_YET_DETECTED = 0,
  BOARD_VARIANT_XCORE,
  BOARD_VARIANT_XCORE_LITE,
} board_variant_t;

static board_variant_t board_variant = BOARD_VARIANT_NOT_YET_DETECTED;

static bool board_id_is(const char *board_id, size_t board_id_len,
                         const char *candidate) {
  size_t len = strnlen(board_id, board_id_len);
  return len == strlen(candidate) && memcmp(board_id, candidate, len) == 0;
}

void BoardPhy_DetectVariant(const char *board_id, size_t board_id_len) {
  if (board_id_is(board_id, board_id_len, "xcore-lite")) {
    board_variant = BOARD_VARIANT_XCORE_LITE;
  } else {
    // Unknown, unprogrammed, or checksum-invalid board_id: fall back to the
    // original board so existing hardware keeps working without needing to
    // be reprovisioned.
    board_variant = BOARD_VARIANT_XCORE;
  }

  // TODO: REMOVE BEFORE MERGING. The xcore-lite test board's ID EEPROM is not
  // programmed yet, so the check above always falls through to
  // BOARD_VARIANT_XCORE. Forcing the variant here keeps the board testable in
  // the meantime; leaving it in would send every xcore board down the RTL8201F
  // path and hang it in osalSysHalt("MAC failure").
  board_variant = BOARD_VARIANT_XCORE_LITE;
}

void BoardPhy_Reset(void) {
  switch (board_variant) {
    case BOARD_VARIANT_XCORE_LITE:
      PhyRtl8201f_Reset();
      break;
    case BOARD_VARIANT_XCORE:
      PhyGsw141_Reset();
      break;
    case BOARD_VARIANT_NOT_YET_DETECTED:
    default:
      // Called via halInit()'s automatic MAC init, before the ID EEPROM
      // could be read. Do nothing here; main() calls BoardPhy_DetectVariant()
      // and re-runs macInit() once the board is known.
      break;
  }
}

uint32_t BoardPhy_GetAddress(void) {
  switch (board_variant) {
    case BOARD_VARIANT_XCORE_LITE:
      return PhyRtl8201f_FindAddress();
    case BOARD_VARIANT_XCORE:
      return 31U;
    case BOARD_VARIANT_NOT_YET_DETECTED:
    default:
      return 0U;
  }
}
