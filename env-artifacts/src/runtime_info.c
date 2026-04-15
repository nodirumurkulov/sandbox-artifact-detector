#include "runtime_info.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

typedef LONG (WINAPI *RtlGetVersion_t)(OSVERSIONINFOW *);

void get_os_version_string(char *buf, int buf_size) {
    if (!buf || buf_size <= 0) return;
    buf[0] = '\0';

    /* Dynamically resolve RtlGetVersion from ntdll.dll (no linker change). */
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        snprintf(buf, buf_size, "Windows (unknown version)");
        return;
    }

    RtlGetVersion_t pRtlGetVersion =
        (RtlGetVersion_t)GetProcAddress(ntdll, "RtlGetVersion");
    if (!pRtlGetVersion) {
        snprintf(buf, buf_size, "Windows (unknown version)");
        return;
    }

    OSVERSIONINFOW osvi;
    memset(&osvi, 0, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    if (pRtlGetVersion(&osvi) != 0) {
        snprintf(buf, buf_size, "Windows (unknown version)");
        return;
    }

    /* Build >= 22000 is Windows 11, otherwise Windows 10. */
    const char *win_name = (osvi.dwBuildNumber >= 22000) ? "Windows 11" : "Windows 10";

    /* Read DisplayVersion (e.g. "23H2") from registry. */
    char display_ver[32] = "";
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD type = 0, size = sizeof(display_ver);
        if (RegQueryValueExA(hKey, "DisplayVersion", NULL, &type,
                             (LPBYTE)display_ver, &size) != ERROR_SUCCESS) {
            display_ver[0] = '\0';
        }
        RegCloseKey(hKey);
    }

    if (display_ver[0])
        snprintf(buf, buf_size, "%s %s (Build %lu)",
                 win_name, display_ver, (unsigned long)osvi.dwBuildNumber);
    else
        snprintf(buf, buf_size, "%s (Build %lu)",
                 win_name, (unsigned long)osvi.dwBuildNumber);
}

#else
/* Non-Windows stub */
void get_os_version_string(char *buf, int buf_size) {
    if (buf && buf_size > 0)
        snprintf(buf, buf_size, "Non-Windows OS");
}
#endif
