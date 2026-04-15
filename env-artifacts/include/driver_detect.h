#pragma once
#ifdef __cplusplus
extern "C" {
#endif

struct driver_result {
    char name[256];    // driver filename or service name
    char vendor[64];   // e.g., "VMware", "VirtualBox", ""
    int loaded;        // 1 = loaded/active, 0 = not found
};

/**
 * Detects known virtualization drivers / services.
 * results[]: array to fill
 * max_results: number of elements in results[]
 * Returns: number of results filled (0..max_results)
 *
 * Implementation: user-mode enumeration of loaded drivers (Windows PSAPI) and
 * a basic fallback for Linux/macOS.
 */

int detect_virtual_drivers(struct driver_result results[], int max_results);
// returns number of results filled
#ifdef __cplusplus
}
#endif
