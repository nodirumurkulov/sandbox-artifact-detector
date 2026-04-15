#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct vmware_backdoor_result {
    int supported; /* 1 = Windows x86_64 (probe executed); 0 = N/A (other OS/arch) */
    int detected;  /* 1 = VMware intercepted IN and EBX returned 0x564D5868        */
};

/**
 * Probes the VMware I/O backdoor port (0x5658 "VX").
 * Sets EAX=0x564D5868 ("VMXh"), ECX=0x0, DX=0x5658 and executes IN EAX,DX.
 *
 * Windows x86_64 only: implemented via a MASM helper wrapped in SEH.
 * On real hardware the IN causes a GPF (caught by __try/__except) → not VMware.
 * In VMware the hypervisor intercepts the IN and writes 0x564D5868 into EBX.
 *
 * Returns 0 on success, non-zero on error.
 */
int get_vmware_backdoor_info(struct vmware_backdoor_result *result);

#ifdef __cplusplus
}
#endif
