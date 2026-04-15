#pragma once

#include "interactive.h"
#include "rollback.h"
#include <stdbool.h>

/* Bitmask categories for selecting which fixes to apply. */
typedef enum {
    FIX_REGISTRY   = 0x01,
    FIX_FILESYSTEM = 0x02,
    FIX_MAC_SPOOF  = 0x04,
    FIX_SERVICES   = 0x08,
    FIX_DRIVERS    = 0x10,
    FIX_BIOS       = 0x20,
    FIX_ALL_GUEST  = 0x3F   /* all of the above */
} fix_category;

#define FIX_MAX_RESULTS 64

/* Outcome of a single fix action. */
typedef struct {
    char label[128];
    bool success;
    char error[256];
} fix_result;

/* Summary report for an entire remediation run. */
typedef struct {
    fix_result results[FIX_MAX_RESULTS];
    int        count;
    int        succeeded;
    int        failed;
    char       rollback_file[256];
} remediation_report;

/* Central remediation orchestrator.
   - snap:     current scan snapshot (provides artifact lists)
   - fix_mask: bitwise OR of fix_category values
   - manifest: rollback manifest to populate (caller must provide)
   - report:   result report (caller must provide)
   - confirm:  if true, prompt user before applying
   Returns 0 on success, -1 on fatal error. */
int remediate_apply(const scan_snapshot *snap,
                    int fix_mask,
                    rollback_manifest *manifest,
                    remediation_report *report,
                    bool confirm);

/* Individual fix functions (called by remediate_apply). */
void fix_registry_artifacts(const scan_snapshot *snap,
                            rollback_manifest *manifest,
                            remediation_report *report);

void fix_filesystem_artifacts(const scan_snapshot *snap,
                              rollback_manifest *manifest,
                              remediation_report *report);

void fix_mac_address(const scan_snapshot *snap,
                     rollback_manifest *manifest,
                     remediation_report *report);

void fix_vm_services(const scan_snapshot *snap,
                     rollback_manifest *manifest,
                     remediation_report *report);

void fix_vm_drivers(const scan_snapshot *snap,
                    rollback_manifest *manifest,
                    remediation_report *report);

void fix_bios_vendor(const scan_snapshot *snap,
                     rollback_manifest *manifest,
                     remediation_report *report);

/* Print a formatted summary of the remediation report. */
void remediate_print_report(const remediation_report *report);
