#pragma once

#ifdef _WIN32
#include <stdio.h>
#define popen _popen
#define pclose _pclose
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct bios_info {
    char vendor[128];
    char version[128];
    char product[128];
};

/**
 * Fills the provided bios_info structure.
 * Returns 0 on success, non-zero on failure.
 */
int get_bios_info(struct bios_info *info);

#ifdef __cplusplus
}
#endif
