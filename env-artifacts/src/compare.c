#include "compare.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  ANSI colour codes                                                  */
/* ------------------------------------------------------------------ */

#define ANSI_GREEN  "\033[32m"
#define ANSI_RED    "\033[31m"
#define ANSI_YELLOW "\033[33m"
#define ANSI_RESET  "\033[0m"
#define ANSI_BOLD   "\033[1m"

/* ------------------------------------------------------------------ */
/*  compare_snapshots                                                  */
/* ------------------------------------------------------------------ */

int compare_snapshots(const scan_snapshot *before,
                      const scan_snapshot *after,
                      compare_result *result) {
    memset(result, 0, sizeof(*result));

    result->score_before = before->score;
    result->score_after  = after->score;

    /* Match checks by label.  Walk the 'before' array and find
       matching entries in 'after'. */
    int n = before->num_checks;
    if (n > after->num_checks) n = after->num_checks;
    if (n > COMPARE_MAX_ENTRIES) n = COMPARE_MAX_ENTRIES;

    for (int i = 0; i < n; i++) {
        const check_result *b = &before->results[i];

        /* Find matching label in 'after' */
        const check_result *a = NULL;
        for (int j = 0; j < after->num_checks; j++) {
            if (b->label && after->results[j].label &&
                strcmp(b->label, after->results[j].label) == 0) {
                a = &after->results[j];
                break;
            }
        }
        if (!a) continue;

        compare_entry *e = &result->entries[result->count++];
        e->label  = b->label;
        e->before = b->status;
        e->after  = a->status;
        e->weight = b->weight;

        if (b->status == CHECK_FAILED && a->status == CHECK_PASSED)
            result->flipped_pass++;
        else if (b->status == CHECK_PASSED && a->status == CHECK_FAILED)
            result->flipped_fail++;
        else
            result->unchanged++;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  compare_print                                                      */
/* ------------------------------------------------------------------ */

static const char *status_label(check_status s) {
    switch (s) {
        case CHECK_PASSED: return "PASSED";
        case CHECK_FAILED: return "FAILED";
        case CHECK_ERROR:  return "ERROR";
        default:           return "?";
    }
}

void compare_print(const compare_result *result) {
    printf("\n");
    printf("  ==============================================\n");
    printf("  BEFORE / AFTER COMPARISON\n");
    printf("  ==============================================\n\n");

    printf("  %-35s  %-8s   %-8s\n", "Check", "Before", "After");
    printf("  %-35s  %-8s   %-8s\n",
           "-----------------------------------", "--------", "--------");

    for (int i = 0; i < result->count; i++) {
        const compare_entry *e = &result->entries[i];

        const char *arrow;
        const char *colour;

        if (e->before == CHECK_FAILED && e->after == CHECK_PASSED) {
            arrow  = " -> ";
            colour = ANSI_GREEN;
        } else if (e->before == CHECK_PASSED && e->after == CHECK_FAILED) {
            arrow  = " -> ";
            colour = ANSI_RED;
        } else {
            arrow  = "    ";
            colour = ANSI_RESET;
        }

        printf("  %-35s  %s%-8s%s%s%s%-8s%s\n",
               e->label ? e->label : "",
               (e->before == CHECK_FAILED) ? ANSI_RED : ANSI_GREEN,
               status_label(e->before),
               ANSI_RESET,
               arrow,
               colour,
               status_label(e->after),
               ANSI_RESET);
    }

    printf("\n  ----------------------------------------------\n");

    /* Score summary */
    int delta = result->score_before - result->score_after;
    if (delta > 0) {
        printf("  Score: %s%d%s -> %s%d%s (reduced by %s%d%s)\n",
               ANSI_RED, result->score_before, ANSI_RESET,
               ANSI_GREEN, result->score_after, ANSI_RESET,
               ANSI_GREEN, delta, ANSI_RESET);
    } else if (delta < 0) {
        printf("  Score: %d -> %s%d%s (increased by %s%d%s — regression!)\n",
               result->score_before,
               ANSI_RED, result->score_after, ANSI_RESET,
               ANSI_RED, -delta, ANSI_RESET);
    } else {
        printf("  Score: %d -> %d (unchanged)\n",
               result->score_before, result->score_after);
    }

    printf("  Fixed: %s%d%s   Regressed: %s%d%s   Unchanged: %d\n",
           ANSI_GREEN, result->flipped_pass, ANSI_RESET,
           ANSI_RED,   result->flipped_fail, ANSI_RESET,
           result->unchanged);

    printf("  ==============================================\n");
}
