#pragma once

#include "bios.h"
#include "mac_oui.h"
#include "driver_detect.h"
#include "registry_fs.h"
#include "timing.h"
#include "cpuid_check.h"
#include "vmware_backdoor.h"
#include "checks.h"
#include "ui.h"

#ifdef _WIN32
#include "debugger_checks.h"
#endif

#define SNAP_MAX_DRIVERS  64
#define SNAP_MAX_REG      64
#define SNAP_MAX_FS       64
#define SNAP_MAX_CHECKS   32

typedef struct scan_snapshot {
    struct bios_info              bios;
    struct mac_info               mac;
    struct driver_result          drivers[SNAP_MAX_DRIVERS];
    int                           driver_count;
    struct reg_artifact           reg_hits[SNAP_MAX_REG];
    int                           reg_count;
    struct fs_artifact            fs_hits[SNAP_MAX_FS];
    int                           fs_count;
    struct timing_result          timing;
    struct cpuid_result           cpuid;
    struct vmware_backdoor_result vmware;
#ifdef _WIN32
    debugger_result               debugger;
#endif
    check_result                  results[SNAP_MAX_CHECKS];
    int                           num_checks;
    ui_run_metadata               meta;
    int                           score;
    int                           threshold;
} scan_snapshot;

/* interactive_menu now accepts a mutable snapshot (for re-scan updates)
   and an optional baseline (for before/after comparison; may be NULL). */
int  interactive_menu(scan_snapshot *snap, const scan_snapshot *baseline);
void show_detailed_data(const scan_snapshot *snap);
void show_recommendations(const scan_snapshot *snap);
void show_fix_guide(const scan_snapshot *snap);
void show_evasion_playbook(const scan_snapshot *snap);
int  export_html_report(const scan_snapshot *snap);

/* New automation menu handlers (Phase 7) */
void show_auto_remediate(scan_snapshot *snap);
void show_profile_select(scan_snapshot *snap);
void show_host_patches(const scan_snapshot *snap);
void show_comparison(const scan_snapshot *baseline, const scan_snapshot *snap);
void show_rollback_menu(void);
