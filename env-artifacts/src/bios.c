#include "bios.h"
#include <string.h>

#ifdef _WIN32
#include <Windows.h>

int get_bios_info(struct bios_info *info) {
    if (!info) return -1;
    memset(info, 0, sizeof(*info));

    /* Read BIOS info from the registry.
       Windows populates HKLM\HARDWARE\DESCRIPTION\System\BIOS
       from the SMBIOS firmware tables at boot time. */
    HKEY hKey = NULL;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                            "HARDWARE\\DESCRIPTION\\System\\BIOS",
                            0, KEY_READ, &hKey);
    if (rc != ERROR_SUCCESS) return -1;

    DWORD sz;

    /* BIOSVendor → vendor */
    sz = sizeof(info->vendor);
    RegQueryValueExA(hKey, "BIOSVendor", NULL, NULL,
                     (BYTE *)info->vendor, &sz);

    /* BIOSVersion → version */
    sz = sizeof(info->version);
    RegQueryValueExA(hKey, "BIOSVersion", NULL, NULL,
                     (BYTE *)info->version, &sz);

    /* SystemProductName → product */
    sz = sizeof(info->product);
    RegQueryValueExA(hKey, "SystemProductName", NULL, NULL,
                     (BYTE *)info->product, &sz);

    RegCloseKey(hKey);
    return 0;
}

#else
/* Non-Windows fallback */
int get_bios_info(struct bios_info *info) {
    if (!info) return -1;
    memset(info, 0, sizeof(*info));

    strncpy(info->vendor, "Unknown", sizeof(info->vendor)-1);
    strncpy(info->version, "Unknown", sizeof(info->version)-1);
    strncpy(info->product, "Unknown", sizeof(info->product)-1);

    return 0;
}
#endif
