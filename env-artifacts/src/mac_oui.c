#include "mac_oui.h"
#include <string.h>
#include <stdio.h>

#ifdef _WIN32

#include <Windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

// Known Virtualisation OUIs (first 3 bytes)
typedef struct {
    const char *prefix;
    const char *vendor;
} oui_entry;

static const oui_entry known_ouis[] = {
    {"00:05:69", "VMware"},
    {"00:0C:29", "VMware"},
    {"00:1C:14", "VMware"},
    {"00:50:56", "VMware"},
    {"08:00:27", "VirtualBox"},
    {"00:03:FF", "Microsoft Hyper-V"},
    {"00:15:5D", "Microsoft Hyper-V"},
    {"00:1C:42", "Parallels"},
    {"00:16:3E", "Xen"},
    {NULL, NULL}
};

int get_mac_oui(struct mac_info *info) {
    if (!info) return -1;
    memset(info, 0, sizeof(*info));

    IP_ADAPTER_INFO adapter_info[16];
    DWORD buflen = sizeof(adapter_info);

    if (GetAdaptersInfo(adapter_info, &buflen) != ERROR_SUCCESS)
        return -1;

    PIP_ADAPTER_INFO adapter = adapter_info;

    while (adapter) {
        // Skip loopback and non-physical adapters
        if (adapter->Type == MIB_IF_TYPE_ETHERNET && adapter->AddressLength == 6) {
            snprintf(
                info->address,
                sizeof(info->address),
                "%02X:%02X:%02X:%02X:%02X:%02X",
                adapter->Address[0], adapter->Address[1], adapter->Address[2],
                adapter->Address[3], adapter->Address[4], adapter->Address[5]
            );

            // Determine vendor
            char prefix[9];
            snprintf(prefix, sizeof(prefix), "%02X:%02X:%02X",
                     adapter->Address[0], adapter->Address[1], adapter->Address[2]);

            const oui_entry *entry = known_ouis;
            strcpy(info->vendor, "Physical / Unknown");
            while (entry->prefix) {
                if (stricmp(entry->prefix, prefix) == 0) {
                    strncpy(info->vendor, entry->vendor, sizeof(info->vendor)-1);
                    break;
                }
                entry++;
            }
            return 0;  // Use first matching adapter
        }
        adapter = adapter->Next;
    }

    return -1;  // No valid adapter found
}

#elif defined(__linux__)

// Linux fallback (can be extended later)
#include <ifaddrs.h>

int get_mac_oui(struct mac_info *info) {
    if (!info) return -1;
    memset(info, 0, sizeof(*info));

    strncpy(info->address, "00:00:00:00:00:00", sizeof(info->address)-1);
    strncpy(info->vendor,  "Unknown (Linux)", sizeof(info->vendor)-1);
    return 0;
}

#elif defined(__APPLE__)

// macOS fallback (current stub)
#include <ifaddrs.h>

int get_mac_oui(struct mac_info *info) {
    if (!info) return -1;
    memset(info, 0, sizeof(*info));

    strncpy(info->address, "00:00:00:00:00:00", sizeof(info->address)-1);
    strncpy(info->vendor,  "Unknown (macOS)", sizeof(info->vendor)-1);
    return 0;
}

#else

// Generic fallback
int get_mac_oui(struct mac_info *info) {
    if (!info) return -1;
    memset(info, 0, sizeof(*info));
    strncpy(info->vendor, "Unknown", sizeof(info->vendor)-1);
    return 0;
}

#endif
