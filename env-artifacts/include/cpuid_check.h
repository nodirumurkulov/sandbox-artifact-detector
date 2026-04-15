#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cpuid_result {
    int      supported;      /* 1 if x86/x64 CPUID was executed; 0 = N/A (ARM64 etc.) */
    char     arch[32];       /* "x86_64", "x86", "arm64", or "unknown"                 */
    uint32_t leaf_1_ecx;     /* raw ECX value from CPUID leaf EAX=1 (0 if unsupported) */
    int      hypervisor_bit; /* bit 31 of ECX: 1 = hypervisor present flag set         */
};

/**
 * Executes CPUID leaf EAX=1 and tests ECX bit 31 (hypervisor present bit).
 * On non-x86 platforms (e.g. Apple Silicon ARM64), marks the result as
 * not supported so the check is treated as N/A rather than a failure.
 *
 * Returns 0 on success, non-zero on error.
 */
int get_cpuid_info(struct cpuid_result *result);

#ifdef __cplusplus
}
#endif
