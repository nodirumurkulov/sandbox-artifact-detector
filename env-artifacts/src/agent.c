#include "agent.h"
#include "profiles.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#  include <shlobj.h>

/* Task name visible in Windows Task Scheduler */
#define TASK_NAME "EnvArtifactHardening"

/* Config directory under %APPDATA% */
static int get_config_dir(char *buf, size_t size) {
    char appdata[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata) != S_OK)
        return -1;
    snprintf(buf, size, "%s\\env-artifacts", appdata);
    CreateDirectoryA(buf, NULL);
    return 0;
}

static int get_config_path(char *buf, size_t size) {
    char dir[MAX_PATH];
    if (get_config_dir(dir, sizeof(dir)) != 0) return -1;
    snprintf(buf, size, "%s\\agent_config.json", dir);
    return 0;
}

/* Get the full path to the running executable */
static int get_exe_path(char *buf, size_t size) {
    DWORD n = GetModuleFileNameA(NULL, buf, (DWORD)size);
    return (n > 0 && n < size) ? 0 : -1;
}

int agent_install(const char *profile_name, const char *platform_name) {
    /* Save config */
    char config_path[MAX_PATH];
    if (get_config_path(config_path, sizeof(config_path)) != 0) {
        fprintf(stderr, "agent: cannot determine config path\n");
        return -1;
    }

    /* Map profile name to id */
    profile_id pid = PROFILE_LIGHT;
    if (strcmp(profile_name, "moderate") == 0)   pid = PROFILE_MODERATE;
    if (strcmp(profile_name, "aggressive") == 0) pid = PROFILE_AGGRESSIVE;

    /* Map platform name to id */
    hypervisor_platform plat = PLATFORM_VMWARE;
    if (strcmp(platform_name, "vbox") == 0)    plat = PLATFORM_VBOX;
    if (strcmp(platform_name, "kvm") == 0)     plat = PLATFORM_KVM;
    if (strcmp(platform_name, "hyperv") == 0)  plat = PLATFORM_HYPERV;

    if (profile_save_config(pid, plat, config_path) != 0) {
        fprintf(stderr, "agent: cannot save config to %s\n", config_path);
        return -1;
    }

    /* Get detector executable path */
    char exe_path[MAX_PATH];
    if (get_exe_path(exe_path, sizeof(exe_path)) != 0) {
        fprintf(stderr, "agent: cannot determine executable path\n");
        return -1;
    }

    /* Create scheduled task */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "schtasks /create /tn \"%s\" /sc onstart /ru SYSTEM /rl HIGHEST "
             "/tr \"\\\"%s\\\" --auto-fix --profile %s --platform %s --no-interactive\" "
             "/f >nul 2>&1",
             TASK_NAME, exe_path, profile_name, platform_name);

    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "agent: schtasks /create failed (exit code %d)\n", ret);
        return -1;
    }

    printf("  Agent installed successfully.\n");
    printf("  Task name: %s\n", TASK_NAME);
    printf("  Config:    %s\n", config_path);
    printf("  Schedule:  On system start (as SYSTEM)\n");
    return 0;
}

int agent_remove(void) {
    /* Delete the scheduled task */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "schtasks /delete /tn \"%s\" /f >nul 2>&1", TASK_NAME);

    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "agent: schtasks /delete failed (exit code %d)\n", ret);
        return -1;
    }

    /* Remove config file */
    char config_path[MAX_PATH];
    if (get_config_path(config_path, sizeof(config_path)) == 0)
        DeleteFileA(config_path);

    printf("  Agent removed successfully.\n");
    return 0;
}

int agent_is_installed(void) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "schtasks /query /tn \"%s\" >nul 2>&1", TASK_NAME);

    int ret = system(cmd);
    return (ret == 0) ? 1 : 0;
}

#else
/* Non-Windows stubs */

int agent_install(const char *profile_name, const char *platform_name) {
    (void)profile_name; (void)platform_name;
    fprintf(stderr, "agent: scheduled agent is only supported on Windows.\n");
    return -1;
}

int agent_remove(void) {
    fprintf(stderr, "agent: scheduled agent is only supported on Windows.\n");
    return -1;
}

int agent_is_installed(void) {
    return -1;
}

#endif
