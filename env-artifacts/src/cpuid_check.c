/*
 * cpuid_check.c
 * CPUID hypervisor-present bit check (x86/x64 leaf EAX=1, ECX bit 31).
 *
 * Windows  : uses MSVC __cpuid() intrinsic from <intrin.h>
 * macOS/Linux x86_64 : uses clang/GCC __cpuid() macro from <cpuid.h>
 * ARM64 / non-x86    : marks the check as not supported (N/A)
 */

#include "cpuid_check.h"
#include <string.h>

/* ------------------------------------------------------------------
 * Architecture detection
 * ------------------------------------------------------------------ */
#if defined(_M_AMD64) || defined(__x86_64__)
#  define CPUID_ARCH_STR "x86_64"
#  define CPUID_X86      1
#elif defined(_M_IX86) || defined(__i386__)
#  define CPUID_ARCH_STR "x86"
#  define CPUID_X86      1
#elif defined(_M_ARM64) || defined(__aarch64__)
#  define CPUID_ARCH_STR "arm64"
#  define CPUID_X86      0
#else
#  define CPUID_ARCH_STR "unknown"
#  define CPUID_X86      0
#endif

/* ------------------------------------------------------------------
 * Platform CPUID wrapper (x86/x64 only)
 * ------------------------------------------------------------------ */
#if CPUID_X86

#if defined(_WIN32)
#  include <intrin.h>

/* MSVC: __cpuid(int[4], int)  →  regs[0]=EAX, [1]=EBX, [2]=ECX, [3]=EDX */
static void run_cpuid(int leaf,
                      uint32_t *eax, uint32_t *ebx,
                      uint32_t *ecx, uint32_t *edx)
{
    int regs[4];
    __cpuid(regs, leaf);
    *eax = (uint32_t)regs[0];
    *ebx = (uint32_t)regs[1];
    *ecx = (uint32_t)regs[2];
    *edx = (uint32_t)regs[3];
}

#else  /* GCC / Clang (macOS x86_64, Linux x86_64) */
#  include <cpuid.h>

/* <cpuid.h> macro: __cpuid(level, a, b, c, d) */
static void run_cpuid(int leaf,
                      uint32_t *eax, uint32_t *ebx,
                      uint32_t *ecx, uint32_t *edx)
{
    __cpuid((unsigned int)leaf, *eax, *ebx, *ecx, *edx);
}

#endif /* _WIN32 */

#endif /* CPUID_X86 */

/* ------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------ */
int get_cpuid_info(struct cpuid_result *result)
{
    if (!result) return -1;
    memset(result, 0, sizeof(*result));
    strncpy(result->arch, CPUID_ARCH_STR, sizeof(result->arch) - 1);

#if CPUID_X86
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    run_cpuid(1, &eax, &ebx, &ecx, &edx);

    result->supported      = 1;
    result->leaf_1_ecx     = ecx;
    result->hypervisor_bit = (int)((ecx >> 31) & 1u);  /* bit 31 */
#else
    /* Non-x86 platform: CPUID instruction unavailable → N/A */
    result->supported      = 0;
    result->leaf_1_ecx     = 0;
    result->hypervisor_bit = 0;
#endif

    return 0;
}
