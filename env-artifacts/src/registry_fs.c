// src/registry_fs.c
#include "registry_fs.h"
#include <string.h>

#ifdef _WIN32
#include <Windows.h>
#include <Shlwapi.h>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shlwapi.lib")

/* List of registry keys to test.
   Covers VMware (Workstation + ESXi enterprise), VirtualBox, Hyper-V,
   QEMU/KVM, Parallels, and Sandboxie sandbox environments. */
static const char *reg_keys[] = {
    /* ── VMware ─────────────────────────────────────────────── */
    "SOFTWARE\\VMware, Inc.",
    "SOFTWARE\\VMware, Inc.\\VMware Tools",
    "SYSTEM\\CurrentControlSet\\Services\\vmtools",
    "SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
    "SYSTEM\\CurrentControlSet\\Services\\vmci",
    "SYSTEM\\CurrentControlSet\\Services\\VMMemCtl",
    "SYSTEM\\CurrentControlSet\\Services\\vmvss",
    "SYSTEM\\CurrentControlSet\\Services\\VGAuthService",
    "SYSTEM\\CurrentControlSet\\Services\\vm3dmp",
    /* VMware enterprise (ESXi / vSphere) */
    "SYSTEM\\CurrentControlSet\\Services\\pvscsi",
    "SYSTEM\\CurrentControlSet\\Services\\vmxnet3",

    /* ── VirtualBox ─────────────────────────────────────────── */
    "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
    /* ACPI table signatures (checked by Bumblebee loader) */
    "HARDWARE\\ACPI\\DSDT\\VBOX__",
    "HARDWARE\\ACPI\\FADT\\VBOX__",
    "HARDWARE\\ACPI\\RSDT\\VBOX__",
    /* Services & drivers */
    "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
    "SYSTEM\\CurrentControlSet\\Services\\VBoxService",
    "SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
    "SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
    "SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",

    /* ── Hyper-V ────────────────────────────────────────────── */
    "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
    "SYSTEM\\CurrentControlSet\\Services\\vmbus",
    /* Hyper-V integration services (checked by FunkSec ransomware) */
    "SYSTEM\\CurrentControlSet\\Services\\vmicguestinterface",
    "SYSTEM\\CurrentControlSet\\Services\\vmicheartbeat",
    "SYSTEM\\CurrentControlSet\\Services\\vmickvpexchange",
    "SYSTEM\\CurrentControlSet\\Services\\vmicrdv",

    /* ── QEMU / KVM ─────────────────────────────────────────── */
    "SOFTWARE\\QEMU",
    "SYSTEM\\CurrentControlSet\\Services\\vioscsi",
    "SYSTEM\\CurrentControlSet\\Services\\viostor",
    "SYSTEM\\CurrentControlSet\\Services\\netkvm",
    "SYSTEM\\CurrentControlSet\\Services\\BALLOON",
    "SYSTEM\\CurrentControlSet\\Services\\VirtioSerial",
    "SYSTEM\\CurrentControlSet\\Services\\VirtIO-FS Service",

    /* ── Parallels ──────────────────────────────────────────── */
    "SOFTWARE\\Parallels\\Parallels Tools",
    /* Parallels PCI device entries */
    "SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_1AB8&DEV_4005&SUBSYS_04001AB8&REV_00",
    "SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_1AB8&DEV_4000&SUBSYS_04001AB8&REV_00",
    "SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_1AB8&DEV_4006&SUBSYS_04061AB8&REV_00",

    /* ── Sandboxie ──────────────────────────────────────────── */
    "SOFTWARE\\Sandboxie",
    "SYSTEM\\CurrentControlSet\\Services\\SbieDrv",
    NULL
};

/* List of filesystem paths to test.
   Covers VMware (Workstation + ESXi enterprise), VirtualBox, Hyper-V,
   QEMU/KVM, Parallels, and Sandboxie sandbox environments. */
static const char *fs_paths[] = {
    /* ── VMware ─────────────────────────────────────────────── */
    /* Install directories & executables */
    "C:\\Program Files\\VMware\\VMware Tools\\",
    "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
    "C:\\Program Files\\VMware\\VMware Tools\\VMwareHostOpen.exe",
    "C:\\Program Files\\VMware\\VMware Tools\\vmwaretray.exe",
    "C:\\Program Files\\VMware\\VMware Tools\\vmwareuser.exe",
    /* Kernel drivers */
    "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
    "C:\\Windows\\System32\\drivers\\vmmouse.sys",
    "C:\\Windows\\System32\\drivers\\vmci.sys",
    "C:\\Windows\\System32\\drivers\\vmmemctl.sys",
    "C:\\Windows\\System32\\drivers\\vmrawdsk.sys",
    "C:\\Windows\\System32\\drivers\\vm3dmp.sys",
    "C:\\Windows\\System32\\drivers\\vsock.sys",
    /* Enterprise (ESXi / vSphere) */
    "C:\\Windows\\System32\\drivers\\vmxnet3.sys",
    "C:\\Windows\\System32\\drivers\\pvscsii.sys",
    /* Guest API library (checked by Lumma Stealer) */
    "C:\\Windows\\System32\\vmGuestLib.dll",

    /* ── VirtualBox ─────────────────────────────────────────── */
    /* Install directories & executables */
    "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\",
    "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxTray.exe",
    "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxService.exe",
    /* Kernel drivers */
    "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
    "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
    "C:\\Windows\\System32\\drivers\\VBoxSF.sys",
    "C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
    /* DLLs */
    "C:\\Windows\\System32\\VBoxDispD3D.dll",

    /* ── QEMU / KVM (VirtIO drivers) ────────────────────────── */
    "C:\\Windows\\System32\\qemu-ga.exe",
    "C:\\Windows\\System32\\drivers\\balloon.sys",
    "C:\\Windows\\System32\\drivers\\netkvm.sys",
    "C:\\Windows\\System32\\drivers\\pvpanic.sys",
    "C:\\Windows\\System32\\drivers\\viofs.sys",
    "C:\\Windows\\System32\\drivers\\viogpudo.sys",
    "C:\\Windows\\System32\\drivers\\vioinput.sys",
    "C:\\Windows\\System32\\drivers\\viorng.sys",
    "C:\\Windows\\System32\\drivers\\vioscsi.sys",
    "C:\\Windows\\System32\\drivers\\vioser.sys",
    "C:\\Windows\\System32\\drivers\\viostor.sys",

    /* ── Parallels ──────────────────────────────────────────── */
    "C:\\Windows\\System32\\drivers\\prl_fs.sys",
    "C:\\Program Files\\Parallels\\Parallels Tools\\prl_cc.exe",
    "C:\\Program Files\\Parallels\\Parallels Tools\\prl_tools.exe",

    /* ── Sandboxie (checked by Lumma, Agent Tesla, Thanos) ─── */
    "C:\\Windows\\System32\\drivers\\SbieDrv.sys",
    "C:\\Windows\\System32\\SbieDll.dll",

    /* ── Cuckoo Sandbox (checked by Lumma Stealer) ──────────── */
    "C:\\Windows\\System32\\cuckoomon.dll",

    /* ── ANY.RUN sandbox (checked by QakBot) ────────────────── */
    "C:\\Windows\\System32\\drivers\\A3E64E55_pr.sys",

    /* ── Comodo Container ───────────────────────────────────── */
    "C:\\Windows\\System32\\cmdvrt32.dll",
    "C:\\Windows\\System32\\cmdvrt64.dll",

    /* ── Analysis tool DLLs (checked by Lumma Stealer) ──────── */
    "C:\\Windows\\System32\\dir_watch.dll",
    "C:\\Windows\\System32\\pstorec.dll",
    "C:\\Windows\\System32\\wpespy.dll",

    /* ── Generic sandbox directories (StealthServer/MintsLoader) */
    "C:\\analysis",
    "C:\\sandbox",
    NULL
};

int detect_registry_artifacts(struct reg_artifact results[], int max_results) {
    if (!results || max_results <= 0) return 0;

    int found = 0;

    for (int i = 0; reg_keys[i] != NULL && found < max_results; i++) {
        HKEY hKey;
        if (RegOpenKeyExA(
                HKEY_LOCAL_MACHINE,
                reg_keys[i],
                0,
                KEY_READ,
                &hKey) == ERROR_SUCCESS)
        {
            strncpy(results[found].path, reg_keys[i],
                    sizeof(results[found].path) - 1);
            strncpy(results[found].description,
                    "Registry VM artefact",
                    sizeof(results[found].description) - 1);

            found++;
            RegCloseKey(hKey);
        }
    }

    return found;
}

int detect_filesystem_artifacts(struct fs_artifact results[], int max_results) {
    if (!results || max_results <= 0) return 0;

    int found = 0;

    for (int i = 0; fs_paths[i] != NULL && found < max_results; i++) {
        DWORD attrib = GetFileAttributesA(fs_paths[i]);
        if (attrib != INVALID_FILE_ATTRIBUTES) {
            strncpy(results[found].path, fs_paths[i],
                    sizeof(results[found].path) - 1);
            strncpy(results[found].description,
                    "Filesystem VM artefact",
                    sizeof(results[found].description) - 1);

            found++;
        }
    }

    return found;
}

#else

// Non-Windows: do nothing
int detect_registry_artifacts(struct reg_artifact results[], int max_results) {
    (void)results; (void)max_results;
    return 0;
}

int detect_filesystem_artifacts(struct fs_artifact results[], int max_results) {
    (void)results; (void)max_results;
    return 0;
}

#endif
