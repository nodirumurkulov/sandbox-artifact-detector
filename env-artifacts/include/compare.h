#pragma once

#include "interactive.h"

#define COMPARE_MAX_ENTRIES 32

/* One check's before/after transition. */
typedef struct {
    const char  *label;
    check_status before;
    check_status after;
    int          weight;
} compare_entry;

/* Overall comparison result. */
typedef struct {
    compare_entry entries[COMPARE_MAX_ENTRIES];
    int count;
    int score_before;
    int score_after;
    int flipped_pass;   /* FAILED -> PASSED */
    int flipped_fail;   /* PASSED -> FAILED (regression) */
    int unchanged;
} compare_result;

/* Compare two snapshots check-by-check and populate result.
   Returns 0 on success. */
int compare_snapshots(const scan_snapshot *before,
                      const scan_snapshot *after,
                      compare_result *result);

/* Print a formatted comparison table with ANSI colours. */
void compare_print(const compare_result *result);
