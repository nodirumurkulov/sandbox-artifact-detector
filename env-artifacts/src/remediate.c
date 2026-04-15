#include "remediate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  include <windows.h>
#  include <aclapi.h>
#  include <iphlpapi.h>
#  include <direct.h>
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "advapi32.lib")
#else
#  include <unistd.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#endif

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static void ensure_logs_dir(void) {
#ifdef _WIN32
    _mkdir("logs");
#else
    mkdir("logs", 0755);
#endif
}

static bool is_elevated(void) {
#ifdef _WIN32
    BOOL elevated = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev;
        DWORD size = sizeof(elev);
        if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size))
            elevated = elev.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated != FALSE;
#else
    return geteuid() == 0;
#endif
}

#ifdef _WIN32
/* Enable a named privilege (e.g. SE_BACKUP_NAME, SE_RESTORE_NAME)
   in the current process token.  Returns true on success. */
static bool enable_privilege(const char *priv_name) {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueA(NULL, priv_name, &tp.Privileges[0].Luid)) {
        CloseHandle(token);
        return false;
    }

    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(token);

    /* AdjustTokenPrivileges returns TRUE even if not all were assigned */
    return ok && err == ERROR_SUCCESS;
}

/* Enable both SE_BACKUP_NAME and SE_RESTORE_NAME for registry save/load. */
static void enable_registry_privileges(void) {
    enable_privilege(SE_BACKUP_NAME);
    enable_privilege(SE_RESTORE_NAME);
}
#endif

#ifdef _WIN32
/* Take ownership of a file and grant Administrators full control so that
   MoveFileA can rename TrustedInstaller-protected files (e.g. driver .sys). */
static BOOL take_ownership_and_move(const char *src, const char *dst) {
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(),
                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueA(NULL, SE_TAKE_OWNERSHIP_NAME,
                                   &tp.Privileges[0].Luid))
            AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
        CloseHandle(token);
    }

    PSID admin_sid = NULL;
    SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&nt_auth, 2,
                              SECURITY_BUILTIN_DOMAIN_RID,
                              DOMAIN_ALIAS_RID_ADMINS,
                              0, 0, 0, 0, 0, 0, &admin_sid);
    if (admin_sid) {
        SetNamedSecurityInfoA((char *)src, SE_FILE_OBJECT,
                               OWNER_SECURITY_INFORMATION,
                               admin_sid, NULL, NULL, NULL);
    }

    EXPLICIT_ACCESS_A ea;
    memset(&ea, 0, sizeof(ea));
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode        = SET_ACCESS;
    ea.grfInheritance       = NO_INHERITANCE;
    ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType  = TRUSTEE_IS_GROUP;
    ea.Trustee.ptstrName    = (char *)admin_sid;

    PACL new_dacl = NULL;
    SetEntriesInAclA(1, &ea, NULL, &new_dacl);
    if (new_dacl) {
        SetNamedSecurityInfoA((char *)src, SE_FILE_OBJECT,
                               DACL_SECURITY_INFORMATION,
                               NULL, NULL, new_dacl, NULL);
        LocalFree(new_dacl);
    }
    if (admin_sid) FreeSid(admin_sid);

    return MoveFileA(src, dst);
}
#endif

static void add_result(remediation_report *rpt,
                       const char *label, bool success, const char *err) {
    if (rpt->count >= FIX_MAX_RESULTS) return;
    fix_result *r = &rpt->results[rpt->count++];
    snprintf(r->label, sizeof(r->label), "%s", label);
    r->success = success;
    snprintf(r->error, sizeof(r->error), "%s", err ? err : "");
    if (success) rpt->succeeded++;
    else         rpt->failed++;
}

/* ------------------------------------------------------------------ */
/*  Registry artifact removal                                          */
/* ------------------------------------------------------------------ */

void fix_registry_artifacts(const scan_snapshot *snap,
                            rollback_manifest *manifest,
                            remediation_report *report) {
#ifdef _WIN32
    enable_registry_privileges();

    for (int i = 0; i < snap->reg_count; i++) {
        const char *path = snap->reg_hits[i].path;
        char label[256];
        snprintf(label, sizeof(label), "Registry: %s", path);

        /* Determine root key and subkey */
        HKEY root = HKEY_LOCAL_MACHINE;
        const char *subkey = path;
        if (strncmp(path, "HKLM\\", 5) == 0) {
            root = HKEY_LOCAL_MACHINE;
            subkey = path + 5;
        } else if (strncmp(path, "HKCU\\", 5) == 0) {
            root = HKEY_CURRENT_USER;
            subkey = path + 5;
        }

        /* Backup the key — use absolute path so rollback works
           regardless of CWD changes between fix and restore. */
        char backup_path[512];
        {
            char cwd[MAX_PATH];
            GetCurrentDirectoryA(MAX_PATH, cwd);
            snprintf(backup_path, sizeof(backup_path),
                     "%s\\logs\\backup_reg_%d.dat", cwd, i);
        }

        HKEY hKey = NULL;
        LONG rc = RegOpenKeyExA(root, subkey, 0,
                                 KEY_READ | KEY_WRITE, &hKey);
        if (rc != ERROR_SUCCESS) {
            char err[128];
            snprintf(err, sizeof(err), "Cannot open key (error %ld)", rc);
            add_result(report, label, false, err);
            continue;
        }

        /* Save key to backup file */
        ensure_logs_dir();
        rc = RegSaveKeyA(hKey, backup_path, NULL);
        if (rc == ERROR_ALREADY_EXISTS) {
            /* Delete existing backup and retry */
            DeleteFileA(backup_path);
            rc = RegSaveKeyA(hKey, backup_path, NULL);
        }

        if (rc != ERROR_SUCCESS) {
            char err[128];
            snprintf(err, sizeof(err), "RegSaveKey failed (error %ld)", rc);
            add_result(report, label, false, err);
            RegCloseKey(hKey);
            continue;
        }
        RegCloseKey(hKey);

        /* Record rollback entry before deleting */
        rollback_add_entry(manifest, RB_ACTION_REG_DELETE_KEY,
                           path, backup_path,
                           snap->reg_hits[i].description);

        /* Delete the key tree */
        rc = RegDeleteTreeA(root, subkey);
        if (rc == ERROR_SUCCESS) {
            add_result(report, label, true, NULL);
        } else {
            char err[128];
            snprintf(err, sizeof(err), "RegDeleteTree failed (error %ld)", rc);
            add_result(report, label, false, err);
        }
    }
#else
    (void)snap; (void)manifest;
    add_result(report, "Registry: N/A", false, "Registry fixes are Windows-only");
#endif
}

/* ------------------------------------------------------------------ */
/*  Filesystem artifact removal                                        */
/* ------------------------------------------------------------------ */

void fix_filesystem_artifacts(const scan_snapshot *snap,
                              rollback_manifest *manifest,
                              remediation_report *report) {
    for (int i = 0; i < snap->fs_count; i++) {
        /* Copy path and strip trailing slash/backslash (directories like
           "C:\Program Files\VMware\VMware Tools\" have a trailing separator
           that causes MoveFileA to fail with ERROR_INVALID_PARAMETER). */
        char clean[512];
        snprintf(clean, sizeof(clean), "%s", snap->fs_hits[i].path);
        size_t len = strlen(clean);
        while (len > 0 && (clean[len - 1] == '\\' || clean[len - 1] == '/'))
            clean[--len] = '\0';

        const char *path = clean;
        char label[256];
        snprintf(label, sizeof(label), "Filesystem: %s", path);

        /* Build renamed path with .disabled suffix */
        char renamed[512];
        snprintf(renamed, sizeof(renamed), "%s.disabled", path);

#ifdef _WIN32
        if (MoveFileA(path, renamed)) {
            rollback_add_entry(manifest, RB_ACTION_FS_RENAME,
                               renamed, path,
                               snap->fs_hits[i].description);
            add_result(report, label, true, NULL);
        } else {
            DWORD err = GetLastError();
            if (err == ERROR_ACCESS_DENIED) {
                /* TrustedInstaller-protected — take ownership first */
                if (take_ownership_and_move(path, renamed)) {
                    rollback_add_entry(manifest, RB_ACTION_FS_RENAME,
                                       renamed, path,
                                       snap->fs_hits[i].description);
                    add_result(report, label, true, NULL);
                } else if (MoveFileExA(path, renamed,
                                        MOVEFILE_DELAY_UNTIL_REBOOT)) {
                    rollback_add_entry(manifest, RB_ACTION_FS_RENAME,
                                       renamed, path,
                                       snap->fs_hits[i].description);
                    add_result(report, label, true,
                               "Scheduled for rename on next reboot");
                } else {
                    char errmsg[128];
                    snprintf(errmsg, sizeof(errmsg),
                             "MoveFile failed (%lu)", GetLastError());
                    add_result(report, label, false, errmsg);
                }
            } else if (err == ERROR_SHARING_VIOLATION) {
                /* File locked — schedule rename on reboot */
                if (MoveFileExA(path, renamed, MOVEFILE_DELAY_UNTIL_REBOOT)) {
                    rollback_add_entry(manifest, RB_ACTION_FS_RENAME,
                                       renamed, path,
                                       snap->fs_hits[i].description);
                    add_result(report, label, true,
                               "Scheduled for rename on next reboot");
                } else {
                    char errmsg[128];
                    snprintf(errmsg, sizeof(errmsg),
                             "MoveFileEx failed (%lu)", GetLastError());
                    add_result(report, label, false, errmsg);
                }
            } else {
                char errmsg[128];
                snprintf(errmsg, sizeof(errmsg), "MoveFile failed (%lu)", err);
                add_result(report, label, false, errmsg);
            }
        }
#else
        if (rename(path, renamed) == 0) {
            rollback_add_entry(manifest, RB_ACTION_FS_RENAME,
                               renamed, path,
                               snap->fs_hits[i].description);
            add_result(report, label, true, NULL);
        } else {
            add_result(report, label, false, "rename() failed");
        }
#endif
    }
}

/* ------------------------------------------------------------------ */
/*  BIOS vendor spoofing                                               */
/* ------------------------------------------------------------------ */

void fix_bios_vendor(const scan_snapshot *snap,
                     rollback_manifest *manifest,
                     remediation_report *report) {
#ifdef _WIN32
    /* Only fix if the BIOS was flagged as belonging to a VM vendor */
    if (snap->results[0].status != CHECK_FAILED) {
        add_result(report, "BIOS spoof: skipped", true,
                   "BIOS not flagged as virtual");
        return;
    }

    const char *bios_key = "HARDWARE\\DESCRIPTION\\System\\BIOS";
    HKEY hKey = NULL;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, bios_key, 0,
                             KEY_READ | KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) {
        char err[128];
        snprintf(err, sizeof(err), "Cannot open BIOS key (%ld)", rc);
        add_result(report, "BIOS spoof", false, err);
        return;
    }

    /* Save original values for rollback.
       We pack them into the backup field as:
       "BIOSVendor|BIOSVersion|SystemManufacturer|SystemProductName" */
    char orig_vendor[128] = {0}, orig_version[128] = {0};
    char orig_mfg[128] = {0}, orig_product[128] = {0};
    DWORD sz;

    sz = sizeof(orig_vendor);
    RegQueryValueExA(hKey, "BIOSVendor", NULL, NULL,
                     (BYTE *)orig_vendor, &sz);
    sz = sizeof(orig_version);
    RegQueryValueExA(hKey, "BIOSVersion", NULL, NULL,
                     (BYTE *)orig_version, &sz);
    sz = sizeof(orig_mfg);
    RegQueryValueExA(hKey, "SystemManufacturer", NULL, NULL,
                     (BYTE *)orig_mfg, &sz);
    sz = sizeof(orig_product);
    RegQueryValueExA(hKey, "SystemProductName", NULL, NULL,
                     (BYTE *)orig_product, &sz);

    /* Pack originals into backup string */
    char backup[512];
    snprintf(backup, sizeof(backup), "%s|%s|%s|%s",
             orig_vendor, orig_version, orig_mfg, orig_product);

    rollback_add_entry(manifest, RB_ACTION_BIOS_SPOOF,
                       bios_key, backup, "BIOS vendor spoofed");

    /* Write spoofed values — generic real hardware strings */
    const char *new_vendor  = "American Megatrends Inc.";
    const char *new_version = "F.40";
    const char *new_mfg     = "Dell Inc.";
    const char *new_product = "OptiPlex 7090";

    bool ok = true;
    if (RegSetValueExA(hKey, "BIOSVendor", 0, REG_SZ,
                       (const BYTE *)new_vendor,
                       (DWORD)strlen(new_vendor) + 1) != ERROR_SUCCESS)
        ok = false;
    if (RegSetValueExA(hKey, "BIOSVersion", 0, REG_SZ,
                       (const BYTE *)new_version,
                       (DWORD)strlen(new_version) + 1) != ERROR_SUCCESS)
        ok = false;
    if (RegSetValueExA(hKey, "SystemManufacturer", 0, REG_SZ,
                       (const BYTE *)new_mfg,
                       (DWORD)strlen(new_mfg) + 1) != ERROR_SUCCESS)
        ok = false;
    if (RegSetValueExA(hKey, "SystemProductName", 0, REG_SZ,
                       (const BYTE *)new_product,
                       (DWORD)strlen(new_product) + 1) != ERROR_SUCCESS)
        ok = false;

    RegCloseKey(hKey);

    if (ok) {
        add_result(report, "BIOS spoof", true,
                   "BIOS vendor set to American Megatrends / Dell Inc.");
    } else {
        add_result(report, "BIOS spoof", false, "Some registry writes failed");
    }
#else
    (void)snap; (void)manifest;
    add_result(report, "BIOS spoof: N/A", false, "BIOS spoofing is Windows-only");
#endif
}

/* ------------------------------------------------------------------ */
/*  MAC address spoofing                                               */
/* ------------------------------------------------------------------ */

void fix_mac_address(const scan_snapshot *snap,
                     rollback_manifest *manifest,
                     remediation_report *report) {
#ifdef _WIN32
    /* Only fix if the MAC was flagged as belonging to a VM vendor */
    if (snap->results[1].status != CHECK_FAILED) {
        add_result(report, "MAC spoof: skipped", true,
                   "MAC not flagged as virtual");
        return;
    }

    /* -----------------------------------------------------------
     * Step 1 — Use GetAdaptersInfo to find the adapter whose
     *          current MAC matches snap->mac.address.  We need
     *          both the adapter index (to locate its registry
     *          subkey) and the friendly interface name (for the
     *          netsh disable/enable cycle).
     * ----------------------------------------------------------- */
    IP_ADAPTER_INFO adapter_info[16];
    DWORD buflen = sizeof(adapter_info);
    if (GetAdaptersInfo(adapter_info, &buflen) != ERROR_SUCCESS) {
        add_result(report, "MAC spoof", false, "GetAdaptersInfo failed");
        return;
    }

    char iface_name[256] = {0};    /* adapter Name used by netsh */
    char iface_desc[256] = {0};    /* DriverDesc for registry matching */
    bool adapter_found = false;
    unsigned char detected_bytes[6] = {0};

    /* Parse snap->mac.address "XX:XX:XX:XX:XX:XX" into raw bytes */
    {
        unsigned int b[6];
        if (sscanf(snap->mac.address, "%02X:%02X:%02X:%02X:%02X:%02X",
                   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
            for (int i = 0; i < 6; i++) detected_bytes[i] = (unsigned char)b[i];
        }
    }

    PIP_ADAPTER_INFO p = adapter_info;
    while (p) {
        if (p->Type == MIB_IF_TYPE_ETHERNET && p->AddressLength == 6) {
            if (memcmp(p->Address, detected_bytes, 6) == 0) {
                snprintf(iface_name, sizeof(iface_name), "%s", p->AdapterName);
                snprintf(iface_desc, sizeof(iface_desc), "%s", p->Description);
                adapter_found = true;
                break;
            }
        }
        p = p->Next;
    }

    /* Fallback: if exact match failed, take the first Ethernet adapter */
    if (!adapter_found) {
        p = adapter_info;
        while (p) {
            if (p->Type == MIB_IF_TYPE_ETHERNET && p->AddressLength == 6) {
                snprintf(iface_name, sizeof(iface_name), "%s", p->AdapterName);
                snprintf(iface_desc, sizeof(iface_desc), "%s", p->Description);
                adapter_found = true;
                break;
            }
            p = p->Next;
        }
    }

    if (!adapter_found) {
        add_result(report, "MAC spoof", false, "No Ethernet adapter found");
        return;
    }

    /* -----------------------------------------------------------
     * Step 2 — Resolve the friendly interface name that netsh
     *          uses.  GetAdaptersInfo returns the GUID in
     *          AdapterName; the human-friendly name is in the
     *          Interfaces registry or we can query it via the
     *          IP_ADAPTER_ADDRESSES API.  Simplest: read
     *          SYSTEM\CurrentControlSet\Control\Network\
     *          {4D36E972-...}\<GUID>\Connection -> Name.
     * ----------------------------------------------------------- */
    char friendly_name[256] = {0};
    {
        char conn_key[512];
        snprintf(conn_key, sizeof(conn_key),
                 "SYSTEM\\CurrentControlSet\\Control\\Network\\"
                 "{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection",
                 iface_name);
        HKEY hConn = NULL;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, conn_key, 0,
                          KEY_READ, &hConn) == ERROR_SUCCESS) {
            DWORD sz = sizeof(friendly_name);
            RegQueryValueExA(hConn, "Name", NULL, NULL,
                             (BYTE *)friendly_name, &sz);
            RegCloseKey(hConn);
        }
    }
    /* Last resort: use the adapter description */
    if (friendly_name[0] == '\0')
        snprintf(friendly_name, sizeof(friendly_name), "%s", iface_desc);

    /* -----------------------------------------------------------
     * Step 3 — Find the adapter's Class registry subkey by
     *          matching the NetCfgInstanceId to our GUID.
     * ----------------------------------------------------------- */
    const char *adapter_base =
        "SYSTEM\\CurrentControlSet\\Control\\Class\\"
        "{4D36E972-E325-11CE-BFC1-08002BE10318}";

    char adapter_path[512] = {0};
    bool reg_found = false;

    for (int idx = 0; idx <= 30; idx++) {
        char subkey[512];
        snprintf(subkey, sizeof(subkey), "%s\\%04d", adapter_base, idx);

        HKEY hKey = NULL;
        LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0,
                                KEY_READ, &hKey);
        if (rc != ERROR_SUCCESS) continue;

        char inst_id[256] = {0};
        DWORD id_size = sizeof(inst_id);
        RegQueryValueExA(hKey, "NetCfgInstanceId", NULL, NULL,
                         (BYTE *)inst_id, &id_size);
        RegCloseKey(hKey);

        if (stricmp(inst_id, iface_name) == 0) {
            snprintf(adapter_path, sizeof(adapter_path), "%s", subkey);
            reg_found = true;
            break;
        }
    }

    /* Fallback: match by DriverDesc */
    if (!reg_found) {
        for (int idx = 0; idx <= 30; idx++) {
            char subkey[512];
            snprintf(subkey, sizeof(subkey), "%s\\%04d", adapter_base, idx);

            HKEY hKey = NULL;
            LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0,
                                    KEY_READ, &hKey);
            if (rc != ERROR_SUCCESS) continue;

            char desc[256] = {0};
            DWORD desc_size = sizeof(desc);
            RegQueryValueExA(hKey, "DriverDesc", NULL, NULL,
                             (BYTE *)desc, &desc_size);
            RegCloseKey(hKey);

            if (desc[0] != '\0' && stricmp(desc, iface_desc) == 0) {
                snprintf(adapter_path, sizeof(adapter_path), "%s", subkey);
                reg_found = true;
                break;
            }
        }
    }

    if (!reg_found) {
        add_result(report, "MAC spoof", false,
                   "Adapter registry key not found");
        return;
    }

    /* -----------------------------------------------------------
     * Step 4 — Write new MAC to registry + restart adapter.
     * ----------------------------------------------------------- */
    HKEY hKey = NULL;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, adapter_path, 0,
                             KEY_READ | KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) {
        add_result(report, "MAC spoof", false, "Cannot open adapter key");
        return;
    }

    char original_mac[32] = {0};
    DWORD mac_size = sizeof(original_mac);
    RegQueryValueExA(hKey, "NetworkAddress", NULL, NULL,
                     (BYTE *)original_mac, &mac_size);

    /* Record rollback entry with original MAC */
    rollback_add_entry(manifest, RB_ACTION_MAC_CHANGE,
                       adapter_path, original_mac,
                       "MAC address override");

    /* Generate a physical-looking MAC: Dell OUI D4BED9 + 3 random bytes */
    srand((unsigned)time(NULL));
    char new_mac[16];
    snprintf(new_mac, sizeof(new_mac), "D4BED9%02X%02X%02X",
             rand() % 256, rand() % 256, rand() % 256);

    rc = RegSetValueExA(hKey, "NetworkAddress", 0, REG_SZ,
                         (const BYTE *)new_mac,
                         (DWORD)strlen(new_mac) + 1);
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS) {
        char err[128];
        snprintf(err, sizeof(err), "RegSetValueEx failed (%ld)", rc);
        add_result(report, "MAC spoof", false, err);
        return;
    }

    /* Restart adapter via netsh using the real friendly name */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "netsh interface set interface \"%s\" disable >nul 2>&1 && "
             "timeout /t 2 /nobreak >nul 2>&1 && "
             "netsh interface set interface \"%s\" enable >nul 2>&1",
             friendly_name, friendly_name);
    int ret = system(cmd);

    if (ret != 0) {
        char detail[256];
        snprintf(detail, sizeof(detail),
                 "Registry set (MAC: %s), but adapter restart failed "
                 "(interface: \"%s\"). Reboot required.", new_mac, friendly_name);
        add_result(report, "MAC spoof", true, detail);
    } else {
        char detail[128];
        snprintf(detail, sizeof(detail),
                 "New MAC: %s (interface: \"%s\")", new_mac, friendly_name);
        add_result(report, "MAC spoof", true, detail);
    }
    (void)ret;
#else
    (void)snap; (void)manifest;
    add_result(report, "MAC spoof: N/A", false, "MAC spoofing is Windows-only");
#endif
}

/* ------------------------------------------------------------------ */
/*  VM service disabling                                               */
/* ------------------------------------------------------------------ */

void fix_vm_services(const scan_snapshot *snap,
                     rollback_manifest *manifest,
                     remediation_report *report) {
#ifdef _WIN32
    /* Known VM Win32 services (not kernel drivers — those are in fix_vm_drivers).
       Covers VMware, VirtualBox, QEMU/KVM, and Parallels. */
    static const char *vm_services[] = {
        /* VMware */
        "VMTools", "VGAuthService", "VM3DService", "vmvss",
        /* VirtualBox */
        "VBoxService",
        /* QEMU / KVM */
        "VirtIO-FS Service", "VirtioSerial", "BALLOON",
        NULL
    };

    for (const char **svc_name = vm_services; *svc_name; svc_name++) {
        SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (!scm) {
            add_result(report, "Service fix", false, "Cannot open SCManager");
            return;
        }

        SC_HANDLE svc = OpenServiceA(scm, *svc_name,
                                      SERVICE_QUERY_CONFIG | SERVICE_STOP |
                                      SERVICE_CHANGE_CONFIG);
        if (!svc) {
            CloseServiceHandle(scm);
            continue; /* Service doesn't exist on this system */
        }

        /* Query current config for rollback */
        DWORD needed = 0;
        QueryServiceConfigA(svc, NULL, 0, &needed);
        LPQUERY_SERVICE_CONFIGA cfg = (LPQUERY_SERVICE_CONFIGA)malloc(needed);
        if (!cfg) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            continue;
        }

        char label[128];
        snprintf(label, sizeof(label), "Service: %s", *svc_name);

        if (QueryServiceConfigA(svc, cfg, needed, &needed)) {
            /* Record original start type */
            char start_str[16];
            snprintf(start_str, sizeof(start_str), "%lu",
                     (unsigned long)cfg->dwStartType);
            rollback_add_entry(manifest, RB_ACTION_SERVICE_DISABLE,
                               *svc_name, start_str,
                               "VM service disabled");

            /* Stop the service */
            SERVICE_STATUS status;
            ControlService(svc, SERVICE_CONTROL_STOP, &status);

            /* Disable it */
            if (ChangeServiceConfigA(svc, SERVICE_NO_CHANGE,
                                      SERVICE_DISABLED,
                                      SERVICE_NO_CHANGE,
                                      NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
                add_result(report, label, true, NULL);
            } else {
                char err[128];
                snprintf(err, sizeof(err), "ChangeServiceConfig failed (%lu)",
                         GetLastError());
                add_result(report, label, false, err);
            }
        } else {
            add_result(report, label, false, "QueryServiceConfig failed");
        }

        free(cfg);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
    }
#else
    (void)snap; (void)manifest;
    add_result(report, "Services: N/A", false, "Service fixes are Windows-only");
#endif
}

/* ------------------------------------------------------------------ */
/*  VM driver disabling                                                */
/* ------------------------------------------------------------------ */

void fix_vm_drivers(const scan_snapshot *snap,
                    rollback_manifest *manifest,
                    remediation_report *report) {
#ifdef _WIN32
    /* Target kernel drivers associated with VM platforms.
       Covers VMware (Workstation + ESXi enterprise), VirtualBox, Hyper-V. */
    static const char *vm_drivers[] = {
        /* VMware core */
        "vmhgfs", "vmci", "vmrawdsk", "vsock", "vmmouse", "vmusbmouse",
        /* VMware 3D graphics */
        "vm3dmp", "vm3dmp-debug", "vm3dmp-stats", "vm3dmp_loader",
        /* VMware memory & storage (enterprise) */
        "VMMemCtl", "pvscsi",
        /* VMware networking (enterprise) */
        "vmxnet", "vmxnet2", "vmxnet3",
        /* VirtualBox */
        "VBoxGuest", "VBoxMouse", "VBoxSF", "VBoxVideo",
        /* Hyper-V */
        "vmbus", "VMBusHID",
        /* Hyper-V integration services */
        "vmicguestinterface", "vmicheartbeat", "vmickvpexchange", "vmicrdv",
        /* QEMU / KVM VirtIO */
        "balloon", "netkvm", "pvpanic", "viofs", "viogpudo",
        "vioinput", "viorng", "vioscsi", "vioser", "viostor",
        /* Parallels */
        "prl_fs",
        /* Sandboxie */
        "SbieDrv",
        NULL
    };

    for (const char **drv_name = vm_drivers; *drv_name; drv_name++) {
        SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (!scm) {
            add_result(report, "Driver fix", false, "Cannot open SCManager");
            return;
        }

        SC_HANDLE svc = OpenServiceA(scm, *drv_name,
                                      SERVICE_QUERY_CONFIG | SERVICE_STOP |
                                      SERVICE_CHANGE_CONFIG);
        if (!svc) {
            CloseServiceHandle(scm);
            continue;
        }

        DWORD needed = 0;
        QueryServiceConfigA(svc, NULL, 0, &needed);
        LPQUERY_SERVICE_CONFIGA cfg = (LPQUERY_SERVICE_CONFIGA)malloc(needed);
        if (!cfg) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            continue;
        }

        char label[128];
        snprintf(label, sizeof(label), "Driver: %s", *drv_name);

        if (QueryServiceConfigA(svc, cfg, needed, &needed)) {
            char start_str[16];
            snprintf(start_str, sizeof(start_str), "%lu",
                     (unsigned long)cfg->dwStartType);
            rollback_add_entry(manifest, RB_ACTION_DRIVER_DISABLE,
                               *drv_name, start_str,
                               "VM driver disabled");

            SERVICE_STATUS status;
            ControlService(svc, SERVICE_CONTROL_STOP, &status);

            if (ChangeServiceConfigA(svc, SERVICE_NO_CHANGE,
                                      SERVICE_DISABLED,
                                      SERVICE_NO_CHANGE,
                                      NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
                add_result(report, label, true, NULL);
            } else {
                char err[128];
                snprintf(err, sizeof(err), "ChangeServiceConfig failed (%lu)",
                         GetLastError());
                add_result(report, label, false, err);
            }
        } else {
            add_result(report, label, false, "QueryServiceConfig failed");
        }

        free(cfg);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
    }
#else
    (void)snap; (void)manifest;
    add_result(report, "Drivers: N/A", false, "Driver fixes are Windows-only");
#endif
}

/* ------------------------------------------------------------------ */
/*  Central orchestrator                                               */
/* ------------------------------------------------------------------ */

int remediate_apply(const scan_snapshot *snap,
                    int fix_mask,
                    rollback_manifest *manifest,
                    remediation_report *report,
                    bool confirm) {
    memset(report, 0, sizeof(*report));

    /* Check elevation */
    if (!is_elevated()) {
        printf("\n  WARNING: Not running as Administrator.\n"
               "  Some fixes (registry, services, drivers, MAC) require elevation.\n"
               "  Results may be incomplete.\n\n");
    }

    /* Count applicable fixes */
    int fix_count = 0;
    if (fix_mask & FIX_REGISTRY)   fix_count += snap->reg_count;
    if (fix_mask & FIX_FILESYSTEM) fix_count += snap->fs_count;
    if (fix_mask & FIX_MAC_SPOOF)  fix_count += 1;
    if (fix_mask & FIX_BIOS)       fix_count += 1;
    if (fix_mask & FIX_SERVICES)   fix_count += 1;  /* group */
    if (fix_mask & FIX_DRIVERS)    fix_count += 1;  /* group */

    if (fix_count == 0) {
        printf("  No applicable fixes for the current scan results.\n");
        return 0;
    }

    /* Prompt if confirm mode */
    if (confirm) {
        printf("  About to apply %d fix(es). Continue? [y/N]: ", fix_count);
        fflush(stdout);
        char line[16];
        if (!fgets(line, sizeof(line), stdin))
            return -1;
        if (line[0] != 'y' && line[0] != 'Y') {
            printf("  Aborted.\n");
            return -1;
        }
    }

    /* Initialise rollback manifest */
    rollback_init(manifest, "remediate");

    /* Dispatch fixes.
       Order matters: stop services/drivers BEFORE deleting registry keys,
       because service entries live under HKLM\SYSTEM\CurrentControlSet\Services\
       and the SCM needs them to query/stop the service. */
    if (fix_mask & FIX_SERVICES)
        fix_vm_services(snap, manifest, report);

    if (fix_mask & FIX_DRIVERS)
        fix_vm_drivers(snap, manifest, report);

    if (fix_mask & FIX_REGISTRY)
        fix_registry_artifacts(snap, manifest, report);

    if (fix_mask & FIX_FILESYSTEM)
        fix_filesystem_artifacts(snap, manifest, report);

    if (fix_mask & FIX_MAC_SPOOF)
        fix_mac_address(snap, manifest, report);

    if (fix_mask & FIX_BIOS)
        fix_bios_vendor(snap, manifest, report);

    /* Save rollback manifest */
    ensure_logs_dir();
    rollback_make_filename(report->rollback_file, sizeof(report->rollback_file));
    rollback_save(manifest, report->rollback_file);

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Report printing                                                    */
/* ------------------------------------------------------------------ */

void remediate_print_report(const remediation_report *report) {
    printf("\n");
    printf("  ==============================================\n");
    printf("  REMEDIATION REPORT\n");
    printf("  ==============================================\n");

    for (int i = 0; i < report->count; i++) {
        const fix_result *r = &report->results[i];
        printf("  [%s] %s",
               r->success ? "OK" : "FAIL",
               r->label);
        if (r->error[0])
            printf("  (%s)", r->error);
        printf("\n");
    }

    printf("  ----------------------------------------------\n");
    printf("  Succeeded: %d   Failed: %d   Total: %d\n",
           report->succeeded, report->failed, report->count);

    if (report->rollback_file[0])
        printf("  Rollback file: %s\n", report->rollback_file);

    printf("  ==============================================\n");
}
