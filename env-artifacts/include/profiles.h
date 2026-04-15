#pragma once

#include "interactive.h"
#include "remediate.h"
#include "tips.h"
#include <stdbool.h>

/* Profile identifiers. */
typedef enum {
    PROFILE_LIGHT      = 0,
    PROFILE_MODERATE   = 1,
    PROFILE_AGGRESSIVE = 2,
    PROFILE_COUNT      = 3
} profile_id;

/* Static descriptor for a hardening profile. */
typedef struct {
    profile_id   id;
    const char  *name;
    const char  *description;
    int          fix_mask;       /* bitwise OR of fix_category */
    bool         generate_patch; /* also produce host-side config patch */
    bool         timing_tips;    /* print timing-related advice */
} profile_descriptor;

/* Return a pointer to the static profile descriptor for `id`. */
const profile_descriptor *profile_get(profile_id id);

/* Interactive prompt: print the three profiles and read user choice.
   Returns the chosen profile_id, or -1 on cancel. */
int profile_select_interactive(void);

/* Apply the full profile: remediate guest-side, optionally generate patch
   and print timing advice.
   - snap:     current scan snapshot
   - profile:  which profile to apply
   - platform: target hypervisor (for patch generation)
   - confirm:  prompt before destructive changes
   Returns 0 on success, -1 on error/abort. */
int profile_apply(scan_snapshot *snap,
                  profile_id profile,
                  hypervisor_platform platform,
                  bool confirm);

/* Save a profile + platform selection to a JSON config file (for the agent). */
int profile_save_config(profile_id profile, hypervisor_platform platform,
                        const char *filepath);

/* Load a profile + platform selection from a JSON config file.
   Returns 0 on success. */
int profile_load_config(profile_id *profile, hypervisor_platform *platform,
                        const char *filepath);
