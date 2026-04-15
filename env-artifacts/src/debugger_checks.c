#ifdef _WIN32
#include "debugger_checks.h"
#include <windows.h>
#include <winternl.h>
#include <stdbool.h>

// NtQueryInformationProcess function pointer type
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// ProcessInformationClass values for debugger detection
#define ProcessDebugPort        7
#define ProcessDebugFlags       0x1f
#define ProcessDebugObjectHandle 0x1e

/* Check 1: IsDebuggerPresent API */
static bool check_is_debugger_present(void) {
    return IsDebuggerPresent() != 0;
}

/* Check 2: CheckRemoteDebuggerPresent API */
static bool check_remote_debugger_present(void) {
    BOOL debugger_present = FALSE;
    HANDLE current_process = GetCurrentProcess();

    if (CheckRemoteDebuggerPresent(current_process, &debugger_present)) {
        return debugger_present != 0;
    }

    return false;
}

/* Check 3: Manual PEB->BeingDebugged check */
static bool check_peb_being_debugged(void) {
#ifdef _WIN64
    // Get PEB from TEB on x64
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (peb) {
        return peb->BeingDebugged != 0;
    }
#else
    // Get PEB from TEB on x86
    PPEB peb = (PPEB)__readfsdword(0x30);
    if (peb) {
        return peb->BeingDebugged != 0;
    }
#endif
    return false;
}

#ifdef _WIN64
/* Check 4: ProcessDebugPort via NtQueryInformationProcess */
static void check_process_debug_port(pNtQueryInformationProcess NtQIP, ntquery_check_result *result) {
    if (!NtQIP || !result) return;

    DWORD_PTR debug_port = 0;
    NTSTATUS status = NtQIP(
        GetCurrentProcess(),
        ProcessDebugPort,
        &debug_port,
        sizeof(debug_port),
        NULL
    );

    if (NT_SUCCESS(status)) {
        result->supported = true;
        result->detected = (debug_port != 0);
    } else {
        result->supported = true;
        result->detected = false;
    }
}

/* Check 5: ProcessDebugFlags via NtQueryInformationProcess */
static void check_process_debug_flags(pNtQueryInformationProcess NtQIP, ntquery_check_result *result) {
    if (!NtQIP || !result) return;

    DWORD debug_flags = 0;
    NTSTATUS status = NtQIP(
        GetCurrentProcess(),
        ProcessDebugFlags,
        &debug_flags,
        sizeof(debug_flags),
        NULL
    );

    if (NT_SUCCESS(status)) {
        result->supported = true;
        // Debug flags == 0 means debugger is present (NoDebugInherit flag is cleared)
        result->detected = (debug_flags == 0);
    } else {
        result->supported = true;
        result->detected = false;
    }
}

/* Check 6: ProcessDebugObjectHandle via NtQueryInformationProcess */
static void check_process_debug_object(pNtQueryInformationProcess NtQIP, ntquery_check_result *result) {
    if (!NtQIP || !result) return;

    HANDLE debug_object = NULL;
    NTSTATUS status = NtQIP(
        GetCurrentProcess(),
        ProcessDebugObjectHandle,
        &debug_object,
        sizeof(debug_object),
        NULL
    );

    if (NT_SUCCESS(status)) {
        result->supported = true;
        result->detected = (debug_object != NULL);
    } else {
        result->supported = true;
        result->detected = false;
    }
}
#endif

/* Performs all debugger checks and populates the result structure */
void get_debugger_info(debugger_result *result) {
    if (!result) return;

    // Phase F1 checks
    result->is_debugger_present = check_is_debugger_present();
    result->remote_debugger_present = check_remote_debugger_present();
    result->peb_being_debugged = check_peb_being_debugged();

#ifdef _WIN64
    // Phase F2 checks - dynamically resolve NtQueryInformationProcess
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationProcess NtQIP = NULL;

    if (ntdll) {
        NtQIP = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    }

    if (NtQIP) {
        // NtQueryInformationProcess successfully resolved
        check_process_debug_port(NtQIP, &result->process_debug_port);
        check_process_debug_flags(NtQIP, &result->process_debug_flags);
        check_process_debug_object(NtQIP, &result->process_debug_object);
    } else {
        // Failed to resolve - mark as unsupported
        result->process_debug_port.supported = false;
        result->process_debug_port.detected = false;
        result->process_debug_flags.supported = false;
        result->process_debug_flags.detected = false;
        result->process_debug_object.supported = false;
        result->process_debug_object.detected = false;
    }
#else
    // Not x64 - mark all NtQuery checks as unsupported
    result->process_debug_port.supported = false;
    result->process_debug_port.detected = false;
    result->process_debug_flags.supported = false;
    result->process_debug_flags.detected = false;
    result->process_debug_object.supported = false;
    result->process_debug_object.detected = false;
#endif
}

#endif
