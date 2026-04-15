#include "rollback.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  include <windows.h>
#  include <aclapi.h>
#  include <direct.h>
#  pragma comment(lib, "advapi32.lib")
#else
#  include <sys/stat.h>
#  include <sys/types.h>
#endif

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

#ifdef _WIN32
static void enable_registry_privileges(void) {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return;

    const char *privs[] = { SE_BACKUP_NAME, SE_RESTORE_NAME };
    for (int i = 0; i < 2; i++) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueA(NULL, privs[i], &tp.Privileges[0].Luid))
            AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
    }
    CloseHandle(token);
}
#endif

static void ensure_logs_dir(void) {
#ifdef _WIN32
    _mkdir("logs");
#else
    mkdir("logs", 0755);
#endif
}

#ifdef _WIN32
/* Take ownership of a file and grant Administrators full control so that
   MoveFileA can rename TrustedInstaller-protected files (e.g. driver .sys). */
static BOOL take_ownership_and_move(const char *src, const char *dst) {
    /* Enable SeTakeOwnership privilege */
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

    /* Make Administrators the owner */
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

    /* Grant Administrators full control */
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

/* Minimal JSON string escaper — handles backslash and double quote. */
static void json_escape(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j + 1 < dst_size; ++i) {
        char c = src[i];
        if (c == '\\' || c == '\"') {
            if (j + 2 >= dst_size) break;
            dst[j++] = '\\';
            dst[j++] = c;
        } else {
            dst[j++] = c;
        }
    }
    dst[j] = '\0';
}

/* Return the name string for an action type. */
static const char *action_type_name(rollback_action_type t) {
    switch (t) {
        case RB_ACTION_REG_DELETE_KEY:  return "reg_delete_key";
        case RB_ACTION_FS_RENAME:       return "fs_rename";
        case RB_ACTION_MAC_CHANGE:      return "mac_change";
        case RB_ACTION_SERVICE_DISABLE: return "service_disable";
        case RB_ACTION_DRIVER_DISABLE:  return "driver_disable";
        case RB_ACTION_BIOS_SPOOF:     return "bios_spoof";
        default:                        return "unknown";
    }
}

/* Parse an action type string back to its enum value. Returns -1 on failure. */
static int parse_action_type(const char *s, rollback_action_type *out) {
    if (strcmp(s, "reg_delete_key")  == 0) { *out = RB_ACTION_REG_DELETE_KEY;  return 0; }
    if (strcmp(s, "fs_rename")       == 0) { *out = RB_ACTION_FS_RENAME;       return 0; }
    if (strcmp(s, "mac_change")      == 0) { *out = RB_ACTION_MAC_CHANGE;      return 0; }
    if (strcmp(s, "service_disable") == 0) { *out = RB_ACTION_SERVICE_DISABLE; return 0; }
    if (strcmp(s, "driver_disable")  == 0) { *out = RB_ACTION_DRIVER_DISABLE;  return 0; }
    if (strcmp(s, "bios_spoof")     == 0) { *out = RB_ACTION_BIOS_SPOOF;     return 0; }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

void rollback_init(rollback_manifest *m, const char *profile_name) {
    memset(m, 0, sizeof(*m));
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(m->timestamp, sizeof(m->timestamp), "%Y-%m-%d %H:%M:%S", t);
    if (profile_name)
        snprintf(m->profile, sizeof(m->profile), "%s", profile_name);
    else
        snprintf(m->profile, sizeof(m->profile), "manual");
}

int rollback_add_entry(rollback_manifest *m,
                       rollback_action_type type,
                       const char *target,
                       const char *backup,
                       const char *desc) {
    if (m->count >= RB_MAX_ENTRIES)
        return -1;
    rollback_entry *e = &m->entries[m->count++];
    e->type = type;
    snprintf(e->target,      sizeof(e->target),      "%s", target ? target : "");
    snprintf(e->backup,      sizeof(e->backup),      "%s", backup ? backup : "");
    snprintf(e->description, sizeof(e->description), "%s", desc   ? desc   : "");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  JSON serialisation                                                 */
/* ------------------------------------------------------------------ */

int rollback_save(const rollback_manifest *m, const char *filepath) {
    ensure_logs_dir();

    FILE *f = fopen(filepath, "w");
    if (!f) {
        fprintf(stderr, "rollback: cannot write %s\n", filepath);
        return -1;
    }

    char esc[1024];

    fprintf(f, "{\n");
    json_escape(m->timestamp, esc, sizeof(esc));
    fprintf(f, "  \"timestamp\": \"%s\",\n", esc);
    json_escape(m->profile, esc, sizeof(esc));
    fprintf(f, "  \"profile\": \"%s\",\n", esc);
    fprintf(f, "  \"entries\": [\n");

    for (int i = 0; i < m->count; i++) {
        const rollback_entry *e = &m->entries[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"type\": \"%s\",\n", action_type_name(e->type));
        json_escape(e->target, esc, sizeof(esc));
        fprintf(f, "      \"target\": \"%s\",\n", esc);
        json_escape(e->backup, esc, sizeof(esc));
        fprintf(f, "      \"backup\": \"%s\",\n", esc);
        json_escape(e->description, esc, sizeof(esc));
        fprintf(f, "      \"description\": \"%s\"\n", esc);
        fprintf(f, "    }%s\n", (i + 1 < m->count) ? "," : "");
    }

    fprintf(f, "  ]\n");
    fprintf(f, "}\n");

    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  JSON parsing (minimal hand-written parser)                         */
/* ------------------------------------------------------------------ */

/* Skip whitespace. */
static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

/* Extract a JSON string value at p (must point to opening '"').
   Writes unescaped content into dst and returns pointer past closing '"'. */
static const char *parse_json_string(const char *p, char *dst, size_t dst_size) {
    if (*p != '"') { dst[0] = '\0'; return p; }
    p++; /* skip opening quote */
    size_t j = 0;
    while (*p && *p != '"') {
        if (*p == '\\' && *(p + 1)) {
            p++;
            if (j + 1 < dst_size) dst[j++] = *p;
            p++;
        } else {
            if (j + 1 < dst_size) dst[j++] = *p;
            p++;
        }
    }
    dst[j] = '\0';
    if (*p == '"') p++; /* skip closing quote */
    return p;
}

/* Find the value after a "key": pattern. Returns pointer to value start, or NULL. */
static const char *find_json_key(const char *json, const char *key) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return NULL;
    p += strlen(needle);
    p = skip_ws(p);
    if (*p == ':') p++;
    p = skip_ws(p);
    return p;
}

int rollback_load(rollback_manifest *m, const char *filepath) {
    memset(m, 0, sizeof(*m));

    FILE *f = fopen(filepath, "r");
    if (!f) {
        fprintf(stderr, "rollback: cannot open %s\n", filepath);
        return -1;
    }

    /* Read entire file */
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > 1024 * 1024) {
        fclose(f);
        return -1;
    }
    char *json = (char *)malloc((size_t)fsize + 1);
    if (!json) { fclose(f); return -1; }
    fread(json, 1, (size_t)fsize, f);
    json[fsize] = '\0';
    fclose(f);

    /* Parse top-level fields */
    const char *p;
    if ((p = find_json_key(json, "timestamp")) != NULL)
        parse_json_string(p, m->timestamp, sizeof(m->timestamp));
    if ((p = find_json_key(json, "profile")) != NULL)
        parse_json_string(p, m->profile, sizeof(m->profile));

    /* Parse entries array */
    p = find_json_key(json, "entries");
    if (!p || *p != '[') { free(json); return 0; }
    p++; /* skip '[' */

    while (m->count < RB_MAX_ENTRIES) {
        p = skip_ws(p);
        if (*p == ']' || *p == '\0') break;
        if (*p == ',') { p++; continue; }
        if (*p != '{') { p++; continue; }

        /* Find the closing '}' for this object */
        const char *obj_start = p;
        int depth = 1;
        p++;
        while (*p && depth > 0) {
            if (*p == '{') depth++;
            else if (*p == '}') depth--;
            if (depth > 0) p++;
        }
        const char *obj_end = p;
        if (*p == '}') p++; /* move past '}' */

        /* Extract fields from the object substring */
        /* We need a temporary null-terminated copy */
        size_t obj_len = (size_t)(obj_end - obj_start) + 1;
        char *obj = (char *)malloc(obj_len + 1);
        if (!obj) break;
        memcpy(obj, obj_start, obj_len);
        obj[obj_len] = '\0';

        rollback_entry *e = &m->entries[m->count];
        memset(e, 0, sizeof(*e));

        char type_str[64] = {0};
        const char *v;
        if ((v = find_json_key(obj, "type")) != NULL)
            parse_json_string(v, type_str, sizeof(type_str));
        if ((v = find_json_key(obj, "target")) != NULL)
            parse_json_string(v, e->target, sizeof(e->target));
        if ((v = find_json_key(obj, "backup")) != NULL)
            parse_json_string(v, e->backup, sizeof(e->backup));
        if ((v = find_json_key(obj, "description")) != NULL)
            parse_json_string(v, e->description, sizeof(e->description));

        if (parse_action_type(type_str, &e->type) == 0)
            m->count++;

        free(obj);
    }

    free(json);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Rollback execution                                                 */
/* ------------------------------------------------------------------ */

int rollback_execute(const rollback_manifest *m, bool verbose) {
    int restored = 0;

#ifdef _WIN32
    enable_registry_privileges();
#endif

    if (verbose)
        printf("  Rollback: %d entries to restore (profile: %s)\n",
               m->count, m->profile);

    /* Iterate in reverse order */
    for (int i = m->count - 1; i >= 0; i--) {
        const rollback_entry *e = &m->entries[i];

        if (verbose)
            printf("  [%d] %s: %s\n", m->count - i, action_type_name(e->type),
                   e->description);

        switch (e->type) {
#ifdef _WIN32
        case RB_ACTION_REG_DELETE_KEY: {
            /* Restore registry key from backup .dat file using RegRestoreKeyA */
            HKEY hKey = NULL;
            /* Parse root key and subkey from target path */
            HKEY root = HKEY_LOCAL_MACHINE;
            const char *subkey = e->target;
            if (strncmp(e->target, "HKLM\\", 5) == 0) {
                root = HKEY_LOCAL_MACHINE;
                subkey = e->target + 5;
            } else if (strncmp(e->target, "HKCU\\", 5) == 0) {
                root = HKEY_CURRENT_USER;
                subkey = e->target + 5;
            }
            LONG rc = RegCreateKeyExA(root, subkey, 0, NULL,
                                       REG_OPTION_BACKUP_RESTORE, KEY_ALL_ACCESS,
                                       NULL, &hKey, NULL);
            if (rc == ERROR_SUCCESS) {
                rc = RegRestoreKeyA(hKey, e->backup, REG_FORCE_RESTORE);
                RegCloseKey(hKey);
                if (rc == ERROR_SUCCESS) {
                    restored++;
                    if (verbose) printf("    -> Registry key restored\n");
                } else {
                    if (verbose) printf("    -> RegRestoreKey failed (%ld)\n", rc);
                }
            } else {
                if (verbose) printf("    -> RegCreateKeyEx failed (%ld)\n", rc);
            }
            break;
        }

        case RB_ACTION_FS_RENAME: {
            /* target = current (renamed) path, backup = original path */
            if (MoveFileA(e->target, e->backup)) {
                restored++;
                if (verbose) printf("    -> File renamed back\n");
            } else {
                DWORD err = GetLastError();
                if (err == ERROR_ACCESS_DENIED) {
                    /* TrustedInstaller-protected file — take ownership first */
                    if (verbose)
                        printf("    -> Access denied, taking ownership...\n");
                    if (take_ownership_and_move(e->target, e->backup)) {
                        restored++;
                        if (verbose) printf("    -> File renamed back (ownership taken)\n");
                    } else {
                        if (verbose)
                            printf("    -> Still failed after ownership (%lu)\n",
                                   GetLastError());
                    }
                } else {
                    if (verbose) printf("    -> MoveFile failed (%lu)\n", err);
                }
            }
            break;
        }

        case RB_ACTION_MAC_CHANGE: {
            /* target = adapter Class registry path (e.g.
               SYSTEM\CurrentControlSet\Control\Class\{4D36E972-...}\0001)
               backup = original MAC string (or empty if none was set) */
            HKEY hKey = NULL;
            LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, e->target, 0,
                                     KEY_READ | KEY_SET_VALUE, &hKey);
            if (rc == ERROR_SUCCESS) {
                /* Read the adapter GUID so we can find the friendly name */
                char inst_id[256] = {0};
                DWORD id_size = sizeof(inst_id);
                RegQueryValueExA(hKey, "NetCfgInstanceId", NULL, NULL,
                                 (BYTE *)inst_id, &id_size);

                if (e->backup[0] == '\0') {
                    /* Original had no override — delete the value */
                    RegDeleteValueA(hKey, "NetworkAddress");
                } else {
                    RegSetValueExA(hKey, "NetworkAddress", 0, REG_SZ,
                                   (const BYTE *)e->backup,
                                   (DWORD)strlen(e->backup) + 1);
                }
                RegCloseKey(hKey);

                /* Look up the friendly interface name from the
                   Network\{GUID}\Connection registry key */
                char friendly[256] = {0};
                if (inst_id[0] != '\0') {
                    char conn_key[512];
                    snprintf(conn_key, sizeof(conn_key),
                             "SYSTEM\\CurrentControlSet\\Control\\Network\\"
                             "{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection",
                             inst_id);
                    HKEY hConn = NULL;
                    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, conn_key, 0,
                                      KEY_READ, &hConn) == ERROR_SUCCESS) {
                        DWORD sz = sizeof(friendly);
                        RegQueryValueExA(hConn, "Name", NULL, NULL,
                                         (BYTE *)friendly, &sz);
                        RegCloseKey(hConn);
                    }
                }

                /* Restart adapter using the real friendly name */
                if (friendly[0] != '\0') {
                    char cmd[512];
                    snprintf(cmd, sizeof(cmd),
                             "netsh interface set interface \"%s\" disable >nul 2>&1 && "
                             "timeout /t 2 /nobreak >nul 2>&1 && "
                             "netsh interface set interface \"%s\" enable >nul 2>&1",
                             friendly, friendly);
                    system(cmd);
                    restored++;
                    if (verbose)
                        printf("    -> MAC address restored (interface: \"%s\")\n",
                               friendly);
                } else {
                    restored++;
                    if (verbose)
                        printf("    -> MAC registry restored (reboot required "
                               "to apply)\n");
                }
            } else {
                if (verbose) printf("    -> RegOpenKeyEx failed (%ld)\n", rc);
            }
            break;
        }

        case RB_ACTION_SERVICE_DISABLE:
        case RB_ACTION_DRIVER_DISABLE: {
            /* target = service name, backup = original start type as string */
            SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
            if (!scm) {
                if (verbose) printf("    -> Cannot open SCManager\n");
                break;
            }
            SC_HANDLE svc = OpenServiceA(scm, e->target,
                                          SERVICE_CHANGE_CONFIG | SERVICE_START);
            if (svc) {
                DWORD start_type = (DWORD)atoi(e->backup);
                if (ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, start_type,
                                          SERVICE_NO_CHANGE, NULL, NULL, NULL,
                                          NULL, NULL, NULL, NULL)) {
                    /* Attempt to start the service */
                    StartServiceA(svc, 0, NULL);
                    restored++;
                    if (verbose) printf("    -> Service re-enabled\n");
                } else {
                    if (verbose) printf("    -> ChangeServiceConfig failed (%lu)\n",
                                        GetLastError());
                }
                CloseServiceHandle(svc);
            } else {
                if (verbose) printf("    -> Cannot open service '%s'\n", e->target);
            }
            CloseServiceHandle(scm);
            break;
        }

        case RB_ACTION_BIOS_SPOOF: {
            /* target = registry key path, backup = "vendor|version|mfg|product" */
            HKEY hKey = NULL;
            LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, e->target, 0,
                                     KEY_SET_VALUE, &hKey);
            if (rc == ERROR_SUCCESS) {
                /* Parse the pipe-delimited backup string */
                char buf[512];
                snprintf(buf, sizeof(buf), "%s", e->backup);

                char *fields[4] = {0};
                fields[0] = buf;
                int fi = 1;
                for (char *p = buf; *p && fi < 4; p++) {
                    if (*p == '|') {
                        *p = '\0';
                        fields[fi++] = p + 1;
                    }
                }

                const char *names[] = {
                    "BIOSVendor", "BIOSVersion",
                    "SystemManufacturer", "SystemProductName"
                };
                bool ok = true;
                for (int f = 0; f < 4 && fields[f]; f++) {
                    if (RegSetValueExA(hKey, names[f], 0, REG_SZ,
                                       (const BYTE *)fields[f],
                                       (DWORD)strlen(fields[f]) + 1)
                            != ERROR_SUCCESS)
                        ok = false;
                }
                RegCloseKey(hKey);
                if (ok) {
                    restored++;
                    if (verbose) printf("    -> BIOS vendor restored\n");
                } else {
                    if (verbose) printf("    -> Some BIOS values failed to restore\n");
                }
            } else {
                if (verbose) printf("    -> RegOpenKeyEx failed (%ld)\n", rc);
            }
            break;
        }
#else
        /* Non-Windows stubs */
        case RB_ACTION_REG_DELETE_KEY:
        case RB_ACTION_MAC_CHANGE:
        case RB_ACTION_BIOS_SPOOF:
        case RB_ACTION_SERVICE_DISABLE:
        case RB_ACTION_DRIVER_DISABLE:
            if (verbose) printf("    -> Not supported on this platform\n");
            break;

        case RB_ACTION_FS_RENAME: {
            if (rename(e->target, e->backup) == 0) {
                restored++;
                if (verbose) printf("    -> File renamed back\n");
            } else {
                if (verbose) printf("    -> rename() failed\n");
            }
            break;
        }
#endif
        default:
            if (verbose) printf("    -> Unknown action type\n");
            break;
        }
    }

    if (verbose)
        printf("  Rollback complete: %d/%d entries restored.\n", restored, m->count);

    return restored;
}

/* ------------------------------------------------------------------ */
/*  Filename generator                                                 */
/* ------------------------------------------------------------------ */

void rollback_make_filename(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buf, size, "logs/rollback_%Y-%m-%d_%H-%M-%S.json", t);
}
