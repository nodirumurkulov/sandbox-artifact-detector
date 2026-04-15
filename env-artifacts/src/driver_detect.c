/* src/driver_detect.c */
#include "driver_detect.h"
#include <string.h>
#include <stdio.h>

/* ---------- Shared type + helper for all OSes ---------- */

typedef struct {
    const char *name;
    const char *vendor;
} known_driver;

static void fill_result(struct driver_result *r,
                        const char *name,
                        const char *vendor)
{
    if (!r) return;
    r->loaded = 1;
    r->name[0] = '\0';
    r->vendor[0] = '\0';
    if (name) strncpy(r->name, name, sizeof(r->name) - 1);
    if (vendor) strncpy(r->vendor, vendor, sizeof(r->vendor) - 1);
}

/* ---------- Windows implementation ---------- */

#if defined(_WIN32) || defined(WIN32)

#define _WIN32_WINNT 0x0600
#include <Windows.h>
#include <Psapi.h>
#include <stdlib.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Advapi32.lib")

static int stricmp_safe(const char *a, const char *b) {
#if defined(_MSC_VER) || defined(_WIN32)
    return _stricmp(a, b);
#else
    return strcasecmp(a, b);
#endif
}

/* Known virtualization drivers / services on Windows.
   Covers VMware Workstation, Player, Fusion, ESXi/vSphere enterprise,
   and Horizon VDI environments as well as VirtualBox and Hyper-V. */
static const known_driver known_drivers_win[] = {
    /* VMware — core */
    {"vmci",           "VMware"},   /* VM Communication Interface */
    {"vmci.sys",       "VMware"},
    {"vmhgfs",         "VMware"},   /* Host-Guest File System */
    {"vmhgfs.sys",     "VMware"},
    {"vmmouse",        "VMware"},   /* Pointing device */
    {"vmmouse.sys",    "VMware"},
    {"vmrawdsk",       "VMware"},   /* Physical Disk Helper */
    {"vmrawdsk.sys",   "VMware"},
    {"vsock",          "VMware"},   /* Virtual Socket */
    {"vsock.sys",      "VMware"},
    {"vmusbmouse",     "VMware"},   /* USB pointing device */
    {"vmvss",          "VMware"},   /* Snapshot provider */
    /* VMware — 3D graphics */
    {"vm3dgl",         "VMware"},   /* OpenGL driver */
    {"vm3dgl.sys",     "VMware"},
    {"vm3dmp",         "VMware"},   /* SVGA 3D miniport */
    {"vm3dmp-debug",   "VMware"},
    {"vm3dmp-stats",   "VMware"},
    {"vm3dmp_loader",  "VMware"},
    /* VMware — memory & storage */
    {"VMMemCtl",       "VMware"},   /* Memory balloon driver */
    {"vmmemctl",       "VMware"},
    {"vmmemctl.sys",   "VMware"},
    {"pvscsi",         "VMware"},   /* Paravirtual SCSI (enterprise ESXi) */
    {"pvscsii.sys",    "VMware"},
    /* VMware — networking (enterprise) */
    {"vmxnet",         "VMware"},   /* Legacy network adapter */
    {"vmxnet.sys",     "VMware"},
    {"vmxnet2",        "VMware"},   /* Enhanced network adapter */
    {"vmxnet3",        "VMware"},   /* Gen-3 paravirtual NIC (enterprise) */
    {"vmxnet3.sys",    "VMware"},
    /* VMware — services */
    {"VMTools",        "VMware"},   /* VMware Tools service */
    {"VGAuthService",  "VMware"},   /* Guest authentication / SSO */
    {"VM3DService",    "VMware"},   /* 3D helper service */
    /* VirtualBox */
    {"VBoxGuest",      "VirtualBox"},
    {"VBoxGuest.sys",  "VirtualBox"},
    {"VBoxService",    "VirtualBox"},
    {"VBoxService.exe","VirtualBox"},
    {"VBoxMouse",      "VirtualBox"},
    {"VBoxMouse.sys",  "VirtualBox"},
    {"VBoxSF",         "VirtualBox"},
    {"VBoxSF.sys",     "VirtualBox"},
    {"VBoxVideo",      "VirtualBox"},
    {"VBoxVideo.sys",  "VirtualBox"},
    {"vboxguest",      "VirtualBox"},
    {"vboxsf",         "VirtualBox"},
    /* QEMU / KVM — VirtIO drivers */
    {"qemu-ga",        "QEMU"},     /* QEMU Guest Agent */
    {"qemu-ga.exe",    "QEMU"},
    {"balloon",        "QEMU"},     /* VirtIO balloon */
    {"balloon.sys",    "QEMU"},
    {"netkvm",         "QEMU"},     /* VirtIO network */
    {"netkvm.sys",     "QEMU"},
    {"pvpanic",        "QEMU"},     /* PV panic device */
    {"pvpanic.sys",    "QEMU"},
    {"viofs",          "QEMU"},     /* VirtIO filesystem */
    {"viofs.sys",      "QEMU"},
    {"viogpudo",       "QEMU"},     /* VirtIO GPU */
    {"viogpudo.sys",   "QEMU"},
    {"vioinput",       "QEMU"},     /* VirtIO input */
    {"vioinput.sys",   "QEMU"},
    {"viorng",         "QEMU"},     /* VirtIO RNG */
    {"viorng.sys",     "QEMU"},
    {"vioscsi",        "QEMU"},     /* VirtIO SCSI */
    {"vioscsi.sys",    "QEMU"},
    {"vioser",         "QEMU"},     /* VirtIO serial */
    {"vioser.sys",     "QEMU"},
    {"viostor",        "QEMU"},     /* VirtIO storage */
    {"viostor.sys",    "QEMU"},
    /* Parallels */
    {"prl_fs",         "Parallels"},/* Parallels filesystem driver */
    {"prl_fs.sys",     "Parallels"},
    /* Sandboxie (checked by Lumma, Agent Tesla, Thanos) */
    {"SbieDll",        "Sandboxie"},
    {"SbieDll.dll",    "Sandboxie"},
    {"SbieDrv",        "Sandboxie"},
    {"SbieDrv.sys",    "Sandboxie"},
    /* Cuckoo Sandbox */
    {"cuckoomon",      "Cuckoo"},
    {"cuckoomon.dll",  "Cuckoo"},
    /* ANY.RUN sandbox (checked by QakBot) */
    {"A3E64E55_pr",    "ANY.RUN"},
    {"A3E64E55_pr.sys","ANY.RUN"},
    /* Comodo Container */
    {"cmdvrt32",       "Comodo"},
    {"cmdvrt32.dll",   "Comodo"},
    {"cmdvrt64",       "Comodo"},
    {"cmdvrt64.dll",   "Comodo"},
    /* Analysis tool DLLs (checked by Lumma Stealer) */
    {"dir_watch",      "iDefense"},
    {"dir_watch.dll",  "iDefense"},
    {"pstorec",        "Sunbelt"},
    {"pstorec.dll",    "Sunbelt"},
    {"wpespy",         "WPE Pro"},
    {"wpespy.dll",     "WPE Pro"},
    /* Hyper-V */
    {"hv_vmbus",       "Hyper-V"},
    {"hv_vmbus.sys",   "Hyper-V"},
    {"vmbus",          "Hyper-V"},
    {"vmbus.sys",      "Hyper-V"},
    {"VMBusHID",       "Hyper-V"},
    /* Hyper-V integration services (checked by FunkSec ransomware) */
    {"vmicguestinterface", "Hyper-V"},
    {"vmicheartbeat",      "Hyper-V"},
    {"vmickvpexchange",    "Hyper-V"},
    {"vmicrdv",            "Hyper-V"},
    {NULL, NULL}
};

int detect_virtual_drivers(struct driver_result results[], int max_results)
{
    if (!results || max_results <= 0) return 0;
    int found = 0;

    /* 1) Enumerate loaded kernel drivers.
     *    A kernel driver may still be loaded in memory even after its service
     *    has been disabled+stopped (kernel modules can't always be unloaded).
     *    Cross-check: if the driver's service is disabled, don't count it. */
    LPVOID drivers[1024];
    DWORD cbNeeded = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded > 0) {
        int cDrivers = (int)(cbNeeded / sizeof(LPVOID));

        /* Open SCM once for all cross-checks */
        SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);

        for (int i = 0; i < cDrivers && found < max_results; ++i) {
            char baseName[MAX_PATH] = {0};
            if (!GetDeviceDriverBaseNameA(drivers[i], baseName, sizeof(baseName)))
                continue;

            for (const known_driver *k = known_drivers_win; k->name; ++k) {
                if (stricmp_safe(baseName, k->name) != 0)
                    continue;

                /* Cross-check: only count this driver if its service is
                   confirmed active (not disabled and config readable).
                   After hardening, registry keys may be deleted while the
                   driver is still loaded in memory — skip those. */
                int skip = 0;
                if (hSCM) {
                    /* Try matching the service by the base name (without .sys) */
                    char svc_name[MAX_PATH];
                    strncpy(svc_name, baseName, sizeof(svc_name) - 1);
                    svc_name[sizeof(svc_name) - 1] = '\0';
                    /* Strip .sys extension if present */
                    char *dot = strrchr(svc_name, '.');
                    if (dot && stricmp_safe(dot, ".sys") == 0)
                        *dot = '\0';

                    SC_HANDLE svc = OpenServiceA(hSCM, svc_name,
                                                  SERVICE_QUERY_CONFIG);
                    if (svc) {
                        int confirmed_active = 0;
                        DWORD needed = 0;
                        if (!QueryServiceConfigA(svc, NULL, 0, &needed) &&
                            GetLastError() == ERROR_INSUFFICIENT_BUFFER &&
                            needed > 0)
                        {
                            LPQUERY_SERVICE_CONFIGA cfg =
                                (LPQUERY_SERVICE_CONFIGA)malloc(needed);
                            if (cfg && QueryServiceConfigA(svc, cfg,
                                                            needed, &needed)) {
                                if (cfg->dwStartType != SERVICE_DISABLED)
                                    confirmed_active = 1;
                            }
                            free(cfg);
                        }
                        /* If config is unreadable (registry backing deleted)
                           or service is disabled, skip this driver */
                        if (!confirmed_active)
                            skip = 1;
                        CloseServiceHandle(svc);
                    } else {
                        /* Service registry key was deleted by hardening —
                           driver is still in memory but won't load on reboot */
                        skip = 1;
                    }
                }

                if (!skip)
                    fill_result(&results[found++], baseName, k->vendor);
                break;
            }
        }

        if (hSCM) CloseServiceHandle(hSCM);
    }

    /* 2) Enumerate driver services — only count those that are NOT disabled.
     *    A disabled service is one whose start type is SERVICE_DISABLED (4).
     *    Our hardening sets drivers to disabled, so we skip those to reflect
     *    the hardened state accurately. */
    SC_HANDLE hSC = OpenSCManagerA(NULL, NULL,
                                    SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
    if (hSC) {
        DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
        EnumServicesStatusExA(hSC, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                              SERVICE_STATE_ALL, NULL, 0,
                              &bytesNeeded, &servicesReturned,
                              &resumeHandle, NULL);
        if (GetLastError() == ERROR_MORE_DATA && bytesNeeded > 0) {
            BYTE *buf = (BYTE *)malloc(bytesNeeded);
            if (buf) {
                if (EnumServicesStatusExA(hSC, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                                          SERVICE_STATE_ALL, buf, bytesNeeded,
                                          &bytesNeeded, &servicesReturned,
                                          &resumeHandle, NULL))
                {
                    ENUM_SERVICE_STATUS_PROCESSA *services =
                        (ENUM_SERVICE_STATUS_PROCESSA *)buf;
                    for (DWORD s = 0; s < servicesReturned && found < max_results; ++s) {
                        const char *svcName = services[s].lpServiceName;
                        const char *display = services[s].lpDisplayName;

                        /* Only count if the service is confirmed active
                           (not disabled, and config is readable).
                           After hardening, registry keys may be deleted while
                           the SCM still caches the service — skip those. */
                        int confirmed_active = 0;
                        SC_HANDLE svc = OpenServiceA(hSC, svcName,
                                                      SERVICE_QUERY_CONFIG);
                        if (svc) {
                            DWORD needed = 0;
                            if (!QueryServiceConfigA(svc, NULL, 0, &needed) &&
                                GetLastError() == ERROR_INSUFFICIENT_BUFFER &&
                                needed > 0)
                            {
                                LPQUERY_SERVICE_CONFIGA cfg =
                                    (LPQUERY_SERVICE_CONFIGA)malloc(needed);
                                if (cfg && QueryServiceConfigA(svc, cfg,
                                                                needed, &needed)) {
                                    if (cfg->dwStartType != SERVICE_DISABLED)
                                        confirmed_active = 1;
                                }
                                free(cfg);
                            }
                            CloseServiceHandle(svc);
                        }
                        if (!confirmed_active)
                            continue;

                        for (const known_driver *k = known_drivers_win; k->name; ++k) {
                            if ((svcName  && stricmp_safe(svcName,  k->name) == 0) ||
                                (display && stricmp_safe(display, k->name) == 0))
                            {
                                fill_result(&results[found++], svcName, k->vendor);
                                break;
                            }
                        }
                    }
                }
                free(buf);
            }
        }
        CloseServiceHandle(hSC);
    }

    return found;
}

/* ---------- Linux implementation ---------- */

#elif defined(__linux__)

#include <stdio.h>

static const known_driver known_drivers_linux[] = {
    {"vboxguest",      "VirtualBox"},
    {"vboxsf",         "VirtualBox"},
    {"vboxvideo",      "VirtualBox"},
    {"vmw_vmci",       "VMware"},
    {"vmw_vmmemctl",   "VMware"},
    {"vmw_balloon",    "VMware"},
    {"vmw_pvscsi",     "VMware"},
    {"vmxnet3",        "VMware"},
    {"vmxnet",         "VMware"},
    {"hv_vmbus",       "Hyper-V"},
    {"hv_storvsc",     "Hyper-V"},
    {"hv_netvsc",      "Hyper-V"},
    {"hv_utils",       "Hyper-V"},
    {"xen_netfront",   "Xen"},
    {"xen_blkfront",   "Xen"},
    {"virtio_pci",     "QEMU"},
    {"virtio_net",     "QEMU"},
    {"virtio_blk",     "QEMU"},
    {"virtio_scsi",    "QEMU"},
    {"qemu_fw_cfg",    "QEMU"},
    {"prl_fs",         "Parallels"},
    {"prl_eth",        "Parallels"},
    {"prl_tg",         "Parallels"},
    {NULL, NULL}
};

int detect_virtual_drivers(struct driver_result results[], int max_results)
{
    if (!results || max_results <= 0) return 0;
    int found = 0;
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return 0;

    char name[256];
    while (fscanf(f, "%255s", name) == 1 && found < max_results) {
        for (const known_driver *k = known_drivers_linux; k->name; ++k) {
            if (strcmp(name, k->name) == 0) {
                fill_result(&results[found++], name, k->vendor);
                break;
            }
        }
        int c;
        while ((c = fgetc(f)) != EOF && c != '\n') { }
    }
    fclose(f);
    return found;
}

/* ---------- macOS implementation ---------- */

#elif defined(__APPLE__)

#include <stdio.h>

static const known_driver known_drivers_macos[] = {
    {"VBoxGuest",                    "VirtualBox"},
    {"com.virtualbox.kext.VBoxGuest","VirtualBox"},
    {"com.parallels.kext",           "Parallels"},
    {"com.vmware.kext",              "VMware"},
    {NULL, NULL}
};

int detect_virtual_drivers(struct driver_result results[], int max_results)
{
    if (!results || max_results <= 0) return 0;
    int found = 0;

    FILE *p = popen("kextstat -l", "r");
    if (!p) return 0;

    char line[512];
    while (fgets(line, sizeof(line), p) && found < max_results) {
        for (const known_driver *k = known_drivers_macos; k->name; ++k) {
            if (strstr(line, k->name) != NULL) {
                fill_result(&results[found++], k->name, k->vendor);
                break;
            }
        }
    }
    pclose(p);
    return found;
}

/* ---------- Fallback ---------- */

#else

int detect_virtual_drivers(struct driver_result results[], int max_results)
{
    (void)results;
    (void)max_results;
    return 0;
}

#endif
