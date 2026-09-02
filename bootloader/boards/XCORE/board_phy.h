#ifndef BOARD_PHY_H
#define BOARD_PHY_H

#if !defined(_FROM_ASM_)

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Tells the board layer which PHY is fitted, identified by board_id (the
// xcore/xcore-lite ID EEPROM's board_info.board_id field -- not
// necessarily null-terminated, hence the explicit length). Must be called
// once by the application, after it has read the ID EEPROM.
//
// Until this has run, BoardPhy_Reset() / BoardPhy_GetAddress() are no-ops.
// This matters because ChibiOS's halInit() calls the Ethernet MAC driver's
// init (and with it, these two hooks) automatically, before the application
// has had any chance to read the ID EEPROM. That first, board-unaware call
// is therefore harmless by construction; the application calls
// BoardPhy_DetectVariant() and then re-invokes macInit() once the board is
// actually known, and that second pass does the real PHY-specific reset and
// address detection.
void BoardPhy_DetectVariant(const char *board_id, size_t board_id_len);

// Board-specific PHY reset, wired up as BOARD_PHY_RESET() in board_ex.h.
void BoardPhy_Reset(void);

// Board-specific PHY address, wired up as BOARD_PHY_ADDRESS in board_ex.h.
uint32_t BoardPhy_GetAddress(void);

#ifdef __cplusplus
}
#endif

#endif  /* !defined(_FROM_ASM_) */

#endif  // BOARD_PHY_H
