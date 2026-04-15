#include "ui.h"
#include "runtime_info.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

// ANSI color codes
#define ANSI_GREEN  "\x1b[32m"
#define ANSI_RED    "\x1b[31m"
#define ANSI_YELLOW "\x1b[33m"
#define ANSI_CYAN   "\x1b[36m"
#define ANSI_BOLD   "\x1b[1m"
#define ANSI_RESET  "\x1b[0m"

/* Canonical weight table -- used by both scoring (ui_print_verdict)
   and the weight accessor (ui_get_weight). Single source of truth. */
static const struct { const char *label; int weight; } g_weights[] = {
    {"BIOS vendor check",            2},
    {"MAC OUI vendor check",         2},
    {"Virtual driver check",         4},
    {"Registry artefact check",      2},
    {"Filesystem artefact check",    2},
    {"CPUID hypervisor bit",         2},
    {"VMware backdoor I/O port",     2},
    {NULL, 0}
};
static const int THRESHOLD = 6;

/* ------------------------------------------------------------------ */
/*  New functions                                                      */
/* ------------------------------------------------------------------ */

int ui_get_weight(const char *label) {
    if (!label) return 0;
    for (int i = 0; g_weights[i].label; i++)
        if (strcmp(label, g_weights[i].label) == 0)
            return g_weights[i].weight;
    return 0;
}

void ui_collect_metadata(ui_run_metadata *meta, const char *tag, bool verbose) {
    if (!meta) return;
    memset(meta, 0, sizeof(*meta));

    /* Timestamp */
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(meta->timestamp, sizeof(meta->timestamp), "%Y-%m-%d %H:%M:%S", t);

    /* Build config */
#ifdef NDEBUG
    snprintf(meta->build_config, sizeof(meta->build_config), "Release");
#else
    snprintf(meta->build_config, sizeof(meta->build_config), "Debug");
#endif

    /* OS version */
    get_os_version_string(meta->os_version, sizeof(meta->os_version));

    /* Architecture */
    snprintf(meta->architecture, sizeof(meta->architecture), "x64");

    /* Tag and verbose */
    if (tag)
        snprintf(meta->run_tag, sizeof(meta->run_tag), "%s", tag);
    meta->verbose = verbose;
}

void ui_print_header_ex(const ui_run_metadata *meta) {
    printf("==============================================\n");
    printf("  ENV-ARTIFACT DETECTOR v1.1.0\n");
    printf("==============================================\n");
    printf("  Timestamp : %s\n", meta->timestamp);
    printf("  Build     : %s\n", meta->build_config);
    printf("  OS        : %s\n", meta->os_version);
    printf("  Arch      : %s\n", meta->architecture);
    printf("  Run tag   : %s\n", meta->run_tag);
    if (meta->verbose)
        printf("  Verbose   : enabled\n");
    printf("==============================================\n");
    printf("  PASSED = no artifact found; FAILED = artifact detected\n");
    printf("==============================================\n");
}

void ui_print_section_title(const char *title) {
    printf("\n  " ANSI_CYAN ANSI_BOLD "--- %s ---" ANSI_RESET "\n", title);
}

void ui_print_check(const check_result *r, int indent, bool verbose) {
    if (!r || !r->label) return;

    /* Determine the label to display (strip leading spaces for measurement) */
    const char *display_label = r->label;

    /* Print indent */
    for (int i = 0; i < indent; i++) putchar(' ');

    /* Calculate padding: we want total label+dots to be ~40 chars from indent */
    int label_len = (int)strlen(display_label);
    int total_width = 40;
    int dots = total_width - label_len;
    if (dots < 2) dots = 2;

    printf("%s ", display_label);
    for (int i = 0; i < dots; i++) putchar('.');

    /* Status with color */
    switch (r->status) {
        case CHECK_PASSED:
            printf(" " ANSI_GREEN "PASSED" ANSI_RESET);
            break;
        case CHECK_FAILED:
            printf(" " ANSI_RED "FAILED" ANSI_RESET);
            break;
        case CHECK_ERROR:
            printf(" " ANSI_YELLOW "ERROR" ANSI_RESET);
            break;
        default:
            printf(" UNKNOWN");
            break;
    }

    /* Weight annotation */
    if (r->status == CHECK_FAILED && r->weight > 0)
        printf("  (+%d)", r->weight);
    else
        printf("  (+0)");

    printf("\n");

    /* Verbose reason line */
    if (verbose && r->status == CHECK_FAILED) {
        for (int i = 0; i < indent; i++) putchar(' ');
        printf("    - Reason: %s\n", (r->reason && r->reason[0]) ? r->reason : "(not provided)");
    }
}

/* ------------------------------------------------------------------ */
/*  Existing functions (signatures preserved)                          */
/* ------------------------------------------------------------------ */

void ui_enable_ansi_if_possible(void) {
#ifdef _WIN32
    // Enable ANSI escape sequences on Windows 10+
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
#endif
    // On non-Windows systems, ANSI is typically supported by default
}

void ui_print_header(void) {
    printf("===========================================\n");
    printf("  ENV-ARTIFACT DETECTOR CHECKS DASHBOARD \n");
    printf("  PASSED = no artifact; FAILED = artifact found\n");
    printf("===========================================\n\n");
}

void ui_print_status(const char *label, check_status st) {
    // Print label with padding (40 characters total, filled with dots)
    printf("%-30s", label);

    // Print dots to fill space
    printf(" .......... ");

    // Print colored status
    switch (st) {
        case CHECK_PASSED:
            printf(ANSI_GREEN "PASSED" ANSI_RESET "\n");
            break;
        case CHECK_FAILED:
            printf(ANSI_RED "FAILED" ANSI_RESET "\n");
            break;
        case CHECK_ERROR:
            printf(ANSI_YELLOW "ERROR" ANSI_RESET "\n");
            break;
        default:
            printf("UNKNOWN\n");
            break;
    }
}

void ui_print_verdict(const check_result *results, int count) {
    int score        = 0;
    int timing_fails = 0;
    int timing_total = 0;

    for (int i = 0; i < count; i++) {
        const char  *lbl = results[i].label  ? results[i].label  : "";
        check_status st  = results[i].status;

        /* Timing checks: matched by "Timing" prefix, scored as a group. */
        if (strncmp(lbl, "Timing", 6) == 0) {
            timing_total++;
            if (st == CHECK_FAILED) timing_fails++;
            continue;
        }

        /* Non-timing checks: add per-check weight on FAILED. */
        if (st == CHECK_FAILED) {
            for (int w = 0; g_weights[w].label != NULL; w++) {
                if (strcmp(lbl, g_weights[w].label) == 0) {
                    score += g_weights[w].weight;
                    break;
                }
            }
            /* Unknown labels default to weight 0 -- forward-compatible. */
        }
    }

    /* Timing bonus: +1 only when 2 or more timing checks fail. */
    if (timing_fails >= 2) {
        score += 1;
    }

    printf("==============================================\n");
    printf("  FINAL VERDICT\n");
    printf("==============================================\n");
    printf("  Suspicion score : %d / %d (threshold)\n", score, THRESHOLD);

    if (score >= THRESHOLD) {
        printf("  " ANSI_RED ">> LIKELY VIRTUALISED <<" ANSI_RESET "\n");
    } else {
        printf("  " ANSI_GREEN ">> LIKELY BARE METAL <<" ANSI_RESET "\n");
    }

    printf("==============================================\n");
}
