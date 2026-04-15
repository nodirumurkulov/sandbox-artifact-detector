#include "checks.h"
#include <string.h>
#include <ctype.h>

// Helper function to perform case-insensitive substring search
static int contains_case_insensitive(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;

    size_t haystack_len = strlen(haystack);
    size_t needle_len = strlen(needle);

    if (needle_len > haystack_len) return 0;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        int match = 1;
        for (size_t j = 0; j < needle_len; j++) {
            if (tolower((unsigned char)haystack[i + j]) != tolower((unsigned char)needle[j])) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}

check_status check_bios_vendor(const struct bios_info *bios) {
    // Check if vendor string is empty
    if (!bios || !bios->vendor || strlen(bios->vendor) == 0) {
        return CHECK_ERROR;
    }

    // Check for VM-related strings (case-insensitive)
    const char *vm_vendors[] = {
        "vmware",
        "virtualbox",
        "hyper-v",
        "qemu",
        "xen",
        "kvm",
        "parallels",
        "bochs",
        NULL
    };

    for (int i = 0; vm_vendors[i] != NULL; i++) {
        if (contains_case_insensitive(bios->vendor, vm_vendors[i])) {
            return CHECK_FAILED;
        }
    }

    return CHECK_PASSED;
}

check_status check_mac_oui(const struct mac_info *mac) {
    // Check if vendor string is empty
    if (!mac || !mac->vendor || strlen(mac->vendor) == 0) {
        return CHECK_ERROR;
    }

    // Check for VM-related MAC vendors
    const char *vm_vendors[] = {
        "VMware",
        "VirtualBox",
        "Microsoft Hyper-V",
        "Microsoft Corporation",
        "Xen",
        "QEMU",
        "Parallels",
        "Red Hat",
        NULL
    };

    for (int i = 0; vm_vendors[i] != NULL; i++) {
        if (strstr(mac->vendor, vm_vendors[i]) != NULL) {
            return CHECK_FAILED;
        }
    }

    return CHECK_PASSED;
}

check_status check_virtual_drivers(int driver_count) {
    // Check for invalid driver count
    if (driver_count < 0) {
        return CHECK_ERROR;
    }

    // If any virtual drivers found, check failed
    if (driver_count > 0) {
        return CHECK_FAILED;
    }

    // No virtual drivers found
    return CHECK_PASSED;
}

check_status check_registry_artifacts(int reg_count) {
    if (reg_count < 0) {
        return CHECK_ERROR;
    }
    return (reg_count > 0) ? CHECK_FAILED : CHECK_PASSED;
}

check_status check_filesystem_artifacts(int fs_count) {
    if (fs_count < 0) {
        return CHECK_ERROR;
    }
    return (fs_count > 0) ? CHECK_FAILED : CHECK_PASSED;
}

// Check if sleep timing indicates VM (sleep time significantly off from expected)
check_status check_timing_sleep(const struct timing_result *t) {
    if (!t) {
        return CHECK_ERROR;
    }

    // Calculate the expected sleep time (assume we requested 100ms as baseline)
    // In VMs, sleep can be much longer due to scheduling overhead
    const uint64_t EXPECTED_SLEEP_MS = 100;
    const double TOLERANCE_PERCENT = 20.0;  // Allow 20% deviation

    // Calculate deviation
    double deviation_percent = 0.0;
    if (t->sleep_ms_actual > EXPECTED_SLEEP_MS) {
        deviation_percent = ((double)(t->sleep_ms_actual - EXPECTED_SLEEP_MS) / EXPECTED_SLEEP_MS) * 100.0;
    }

    // If sleep time is significantly higher than expected, likely a VM
    if (deviation_percent > TOLERANCE_PERCENT) {
        return CHECK_FAILED;
    }

    return CHECK_PASSED;
}

// Check if RDTSC behavior indicates VM (inconsistent or unusually low)
check_status check_timing_rdtsc(const struct timing_result *t) {
    if (!t) {
        return CHECK_ERROR;
    }

    // RDTSC delta should be proportional to actual time
    // On a typical 2-3 GHz CPU, 100ms should yield ~200-300 million cycles
    // VMs may show much lower values due to virtualization overhead
    const uint64_t MIN_EXPECTED_CYCLES = 50000000;  // 50M cycles minimum for 100ms

    // If RDTSC delta is suspiciously low, likely a VM
    if (t->rdtsc_delta < MIN_EXPECTED_CYCLES) {
        return CHECK_FAILED;
    }

    // RDTSC should also be reasonably consistent with sleep time
    // Expect roughly 1-4 million cycles per millisecond (1-4 GHz range)
    const uint64_t EXPECTED_SLEEP_MS = 100;
    uint64_t cycles_per_ms = t->rdtsc_delta / EXPECTED_SLEEP_MS;

    // If cycles per ms is way off (< 500K or > 10M), suspicious
    if (cycles_per_ms < 500000 || cycles_per_ms > 10000000) {
        return CHECK_FAILED;
    }

    return CHECK_PASSED;
}

// Check if loop execution timing indicates VM jitter.
// Uses the multi-sample statistical test populated by measure_loop_stats().
check_status check_timing_loop(const struct timing_result *t) {
    if (!t) {
        return CHECK_ERROR;
    }

    return t->loop.passed ? CHECK_PASSED : CHECK_FAILED;
}

// Check CPUID leaf 1 ECX bit 31 (hypervisor present flag)
// Returns PASSED if no hypervisor detected or if the check is N/A (non-x86).
check_status check_cpuid_hypervisor_bit(const struct cpuid_result *r) {
    if (!r) {
        return CHECK_ERROR;
    }

    // Non-x86 platform: CPUID unavailable, treat as N/A (don't fail)
    if (!r->supported) {
        return CHECK_PASSED;
    }

    // Bit 31 set means a hypervisor identified itself
    return r->hypervisor_bit ? CHECK_FAILED : CHECK_PASSED;
}

// Check VMware I/O backdoor port (0x5658).
// Returns PASSED if not detected or if the check is N/A (non-Windows/non-x64).
check_status check_vmware_backdoor(const struct vmware_backdoor_result *r) {
    if (!r) {
        return CHECK_ERROR;
    }

    // Non-Windows or non-x64: probe not supported, treat as N/A (don't fail)
    if (!r->supported) {
        return CHECK_PASSED;
    }

    // VMware intercepted the IN and returned the magic EBX value
    return r->detected ? CHECK_FAILED : CHECK_PASSED;
}

#ifdef _WIN32
// Check debugger detection (any check detecting a debugger = FAILED)
// Returns PASSED if no debugger detected.
check_status check_debugger(const debugger_result *r) {
    if (!r) {
        return CHECK_ERROR;
    }

    // Phase F1 checks
    if (r->is_debugger_present || r->remote_debugger_present || r->peb_being_debugged) {
        return CHECK_FAILED;
    }

    // Phase F2 checks - NtQueryInformationProcess
    // Only consider if supported; ignore unsupported checks
    if (r->process_debug_port.supported && r->process_debug_port.detected) {
        return CHECK_FAILED;
    }
    if (r->process_debug_flags.supported && r->process_debug_flags.detected) {
        return CHECK_FAILED;
    }
    if (r->process_debug_object.supported && r->process_debug_object.detected) {
        return CHECK_FAILED;
    }

    return CHECK_PASSED;
}
#endif
