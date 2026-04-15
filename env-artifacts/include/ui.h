#pragma once
#include "checks.h"
#include <stdbool.h>

/* Bundles a dashboard label with its check outcome for weighted verdict scoring. */
typedef struct {
    const char  *label;
    check_status status;
    int          weight;    /* score contribution; 0 for timing/debugger */
    const char  *reason;    /* failure reason for --verbose; NULL if N/A */
} check_result;

/* Run metadata displayed in the enhanced header and written to JSON. */
typedef struct {
    char timestamp[32];       /* "YYYY-MM-DD HH:MM:SS" */
    char build_config[16];    /* "Debug" or "Release"   */
    char os_version[128];     /* e.g. "Windows 11 23H2 (Build 26200)" */
    char architecture[16];    /* "x64" */
    char run_tag[256];        /* from --tag, or "" */
    bool verbose;             /* from --verbose */
} ui_run_metadata;

/* Populate metadata struct. */
void ui_collect_metadata(ui_run_metadata *meta, const char *tag, bool verbose);

/* Print enhanced header with metadata. */
void ui_print_header_ex(const ui_run_metadata *meta);

/* Print a section title: "--- <title> ---" */
void ui_print_section_title(const char *title);

/* Print a single check line with weight + optional verbose reason. */
void ui_print_check(const check_result *r, int indent, bool verbose);

/* Look up weight for a label from the canonical weight table. */
int ui_get_weight(const char *label);

/* Existing -- retained for backward compatibility. */
void ui_enable_ansi_if_possible(void);
void ui_print_header(void);
void ui_print_status(const char *label, check_status st);
void ui_print_verdict(const check_result *results, int count);
