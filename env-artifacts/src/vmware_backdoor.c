/*
 * vmware_backdoor.c
 * VMware I/O backdoor port detection (Windows x86_64 only).
 *
 * The backdoor works by executing the privileged IN instruction with:
 *   EAX = 0x564D5868 ("VMXh"), ECX = 0x0, DX = 0x5658 ("VX")
 *
 * On bare metal this causes a General Protection Fault (ring-3 cannot use IN
 * on arbitrary ports). __try/__except catches the GPF → not VMware.
 * VMware intercepts the IN before the fault and writes 0x564D5868 into EBX.
 * We detect VMware by confirming EBX holds that magic value.
 *
 * The low-level IN sequence lives in vmware_backdoor_asm.asm (MASM, x64)
 * because MSVC does not support inline __asm on x64 targets.
 */

#include "vmware_backdoor.h"
#include <string.h>

/* ------------------------------------------------------------------
 * Windows x86_64 implementation
 * ------------------------------------------------------------------ */
#if defined(_WIN32) && defined(_M_AMD64)

#include <Windows.h>   /* EXCEPTION_EXECUTE_HANDLER, __try/__except */

/* Low-level MASM probe declared here; defined in vmware_backdoor_asm.asm */
extern uint32_t vmware_backdoor_probe(void);

#define VMWARE_MAGIC 0x564D5868u  /* "VMXh" */

int get_vmware_backdoor_info(struct vmware_backdoor_result *result)
{
    if (!result) return -1;
    memset(result, 0, sizeof(*result));

    result->supported = 1;

    uint32_t ebx = 0;
    int      got_exception = 0;

    __try {
        ebx = vmware_backdoor_probe();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* General Protection Fault: bare-metal host, not VMware */
        got_exception = 1;
    }

    if (!got_exception && ebx == VMWARE_MAGIC) {
        result->detected = 1;
    }

    return 0;
}

#else  /* Non-Windows or non-x64 */

int get_vmware_backdoor_info(struct vmware_backdoor_result *result)
{
    if (!result) return -1;
    memset(result, 0, sizeof(*result));
    /* N/A: VMware backdoor probe only supported on Windows x86_64 */
    result->supported = 0;
    result->detected  = 0;
    return 0;
}

#endif /* _WIN32 && _M_AMD64 */
