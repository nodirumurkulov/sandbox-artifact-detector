#pragma once

#ifdef _WIN32
#include <windows.h>
#include <stdbool.h>

/* Individual NtQueryInformationProcess check result */
typedef struct {
    bool supported;
    bool detected;
} ntquery_check_result;

/* Results from debugger detection checks */
typedef struct {
    // Phase F1 checks
    bool is_debugger_present;
    bool remote_debugger_present;
    bool peb_being_debugged;

    // Phase F2 checks - NtQueryInformationProcess
    ntquery_check_result process_debug_port;
    ntquery_check_result process_debug_flags;
    ntquery_check_result process_debug_object;
} debugger_result;

/* Performs all debugger checks and populates the result structure */
void get_debugger_info(debugger_result *result);

#endif
