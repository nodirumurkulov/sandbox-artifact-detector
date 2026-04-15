#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct mac_info {
    char address[18];   // "XX:XX:XX:XX:XX:XX"
    char vendor[64];    // Virtualisation vendor name or "Physical"
};

/**
 * Retrieves the MAC address of the first active adapter and classifies its OUI.
 * Returns 0 on success, non-zero on failure.
 */
int get_mac_oui(struct mac_info *info);

#ifdef __cplusplus
}
#endif
