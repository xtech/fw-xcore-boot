#include "board_variant.h"

#include <stdbool.h>
#include <string.h>

#include "board_phy.h"

static board_variant_t board_variant = BOARD_VARIANT_NOT_YET_DETECTED;

static bool board_id_is(const char *board_id, size_t board_id_len,
                        const char *candidate) {
  size_t len = strnlen(board_id, board_id_len);
  return len == strlen(candidate) && memcmp(board_id, candidate, len) == 0;
}

void InitBoardVariant(const char *board_id, size_t board_id_len) {
  if (board_id_is(board_id, board_id_len, "xcore-lite")) {
    board_variant = BOARD_VARIANT_XCORE_LITE;
  } else {
    // InitGlobals() has obtained a checksum-valid, nonempty board identity.
    // Preserve the original-xcore fallback for legacy board identifiers.
    board_variant = BOARD_VARIANT_XCORE;
  }

  // Variant-specific setup goes here, one call per subsystem.
  BoardPhy_Init();
}

board_variant_t GetBoardVariant(void) { return board_variant; }
