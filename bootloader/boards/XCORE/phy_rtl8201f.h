#ifndef PHY_RTL8201F_H
#define PHY_RTL8201F_H

#include <stdint.h>

// Resets the RTL8201F PHY via RESET_PHY. Must run with the MAC's ETH clocks
// already enabled, and with the RTOS running (uses chThdSleep()).
void PhyRtl8201f_Reset(void);

// Finds the RTL8201F's MDIO address by scanning 0..31 and matching the PHY
// identifier registers, since the address is set by board strapping
// (RTL8201F datasheet Table 7, LED0/LED1 PHYAD pins) rather than fixed in
// silicon. Halts (osalSysHalt) if no matching PHY answers.
uint32_t PhyRtl8201f_FindAddress(void);

#endif  // PHY_RTL8201F_H
