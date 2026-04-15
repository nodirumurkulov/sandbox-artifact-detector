#pragma once
#include "bios.h"
#include "mac_oui.h"
#include "driver_detect.h"
#include "registry_fs.h"
#include "timing.h"
#include "cpuid_check.h"
#include "vmware_backdoor.h"

#ifdef _WIN32
#include "debugger_checks.h"
#endif

typedef enum {
    CHECK_PASSED = 0,
    CHECK_FAILED = 1,
    CHECK_ERROR  = 2
} check_status;

// environment artefact checks
check_status check_bios_vendor(const struct bios_info *bios);
check_status check_mac_oui(const struct mac_info *mac);
check_status check_virtual_drivers(int driver_count);
check_status check_registry_artifacts(int reg_count);
check_status check_filesystem_artifacts(int fs_count);

// Timing-based checks
check_status check_timing_sleep(const struct timing_result *t);
check_status check_timing_rdtsc(const struct timing_result *t);
check_status check_timing_loop(const struct timing_result *t);

// CPUID-based checks
check_status check_cpuid_hypervisor_bit(const struct cpuid_result *r);

// VMware backdoor I/O port check
check_status check_vmware_backdoor(const struct vmware_backdoor_result *r);

#ifdef _WIN32
// Debugger detection checks
check_status check_debugger(const debugger_result *r);
#endif
