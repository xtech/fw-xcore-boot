#include "phy_rtl8201f.h"

#include "ch.h"
#include "hal.h"
#include "hal_mii.h"

// Reg2/Reg3 default values from the RTL8201F/FL/FN datasheet (Rev. 1.4),
// sections 7.3/7.4: OUI 001Ch, OUI_LSB/model/revision 110010 000001 0110.
#define MII_RTL8201F_ID 0x001CC816U

static bool has_been_reset = false;

void PhyRtl8201f_Reset(void) {
  // ChibiOS's mac_lld_init() calls BOARD_PHY_ADDRESS (-> FindAddress(),
  // below) before BOARD_PHY_RESET() (-> here). The RTL8201F has to be
  // reset and settled before it will answer MDIO, so FindAddress() calls
  // this itself first. This flag makes that safe to call twice per boot:
  // the real reset happens once, and the later BOARD_PHY_RESET() call is a
  // cheap no-op instead of paying the 150ms settle time again.
  if (has_been_reset) {
    return;
  }

  // RESET_PHY (PF3) is configured open-drain in board.h, which works on the
  // original xcore because that board pulls the net up externally. On
  // xcore-lite the net floats, so palSetLine() would only release the pin to
  // Hi-Z and the RTL8201F would sit in permanent hardware reset (measured:
  // PF3 reads 0 in GPIOF->IDR after palSetLine(), and no PHY answers MDIO at
  // any of the 32 addresses). Drive it push-pull instead. Nothing else drives
  // this net -- with just the STM32's ~40k internal pull-up the line already
  // reaches a valid high -- so there is no contention risk.
  palClearLine(LINE_RESET_PHY);
  palSetLineMode(LINE_RESET_PHY, PAL_MODE_OUTPUT_PUSHPULL);

  // RTL8201F datasheet 9.1.3 "Power On and PHY Reset Sequence": PHYRSTB is
  // active low and must be held for at least 10ms, and the PHY register set
  // isn't guaranteed accessible over MDIO until 150ms after PHYRSTB is
  // de-asserted (point B in Figure 20). Unlike the GSW141, no vendor
  // register unlock sequence is needed.
  chThdSleep(TIME_MS2I(15));
  palSetLine(LINE_RESET_PHY);
  chThdSleep(TIME_MS2I(150));

  has_been_reset = true;
}

uint32_t PhyRtl8201f_FindAddress(void) {
  PhyRtl8201f_Reset();

  for (uint32_t i = 0U; i <= 31U; i++) {
    ETHD1.phyaddr = i << ETH_MACMDIOAR_PA_Pos;
    uint32_t reg1 = mii_read(&ETHD1, MII_PHYSID1);
    uint32_t reg2 = mii_read(&ETHD1, MII_PHYSID2);
    if ((reg1 == (MII_RTL8201F_ID >> 16U)) &&
        ((reg2 & 0xFFF0U) ==
         (MII_RTL8201F_ID & 0xFFF0U))) {
      return i;
    }
  }

  /* Wrong or defective board. */
  osalSysHalt("MAC failure");
  return 0U;
}
