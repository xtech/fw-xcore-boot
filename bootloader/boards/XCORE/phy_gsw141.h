#ifndef PHY_GSW141_H
#define PHY_GSW141_H

// Resets and configures the GSW141 PHY (fixed at MDIO address 31 on the
// xcore board). Must run with the MAC's ETH clocks already enabled.
void PhyGsw141_Reset(void);

#endif  // PHY_GSW141_H
