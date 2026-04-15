#include "tips.h"
#include <string.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/*  Multi-method tips + per-platform playbook data for every check     */
/* ------------------------------------------------------------------ */

static const check_tip g_tips[] = {

    /* ---- BIOS vendor check ---- */
    {"BIOS vendor check",
     "Your BIOS vendor string identifies this machine as a virtual machine.",
     4,
     /* methods */
     {
       {"Method 1: Edit VMware config file (.vmx)",
        "1. Shut down the VM completely.\n"
        "2. Find the .vmx file for your VM (usually in the VM folder).\n"
        "3. Open the .vmx file in a text editor.\n"
        "4. Add the line:  smbios.reflectHost = \"TRUE\"\n"
        "5. Save the file and start the VM."},

       {"Method 2: Use VirtualBox command-line tool",
        "1. Shut down the VM.\n"
        "2. Open a terminal or command prompt.\n"
        "3. Run:  VBoxManage setextradata \"VM Name\"\n"
        "         \"VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor\"\n"
        "         \"American Megatrends Inc.\"\n"
        "4. Start the VM."},

       {"Method 3: Use a BIOS spoofing tool",
        "1. Download a BIOS spoofing tool (e.g. SMBIOS-Changer).\n"
        "2. Run it inside the VM as Administrator.\n"
        "3. Set the vendor to a real manufacturer name (Dell, HP, Lenovo, etc.).\n"
        "4. Reboot the VM."},

       {"Method 4: Use Hyper-V / QEMU settings",
        "1. For Hyper-V: use Set-VMFirmware or modify the VM configuration.\n"
        "2. For QEMU/KVM: add  -smbios type=0,vendor=\"American Megatrends Inc.\"\n"
        "   to your QEMU launch command.\n"
        "3. Start the VM and verify the change with a BIOS info tool."}
     },
     /* platforms [VMware, VBox, KVM, Hyper-V] */
     {
       /* VMware */  {"smbios.reflectHost = \"TRUE\"", NULL},
       /* VBox   */  {
           "VBoxManage setextradata \"<VM>\" \"VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor\" \"American Megatrends Inc.\"",
           NULL},
       /* KVM    */  {"-smbios type=0,vendor=\"American Megatrends Inc.\"", NULL},
       /* HyperV */  {"Set-VMFirmware -VMName \"<VM>\" -EnableSecureBoot Off", NULL}
     }
    },

    /* ---- MAC OUI vendor check ---- */
    {"MAC OUI vendor check",
     "Your network adapter's MAC address starts with a prefix registered to a\n"
     "virtualisation vendor, which reveals this is a virtual machine.",
     3,
     {
       {"Method 1: Change MAC address in VMware (.vmx)",
        "1. Shut down the VM.\n"
        "2. Open the .vmx file in a text editor.\n"
        "3. Change  ethernet0.address  to a MAC that starts with a real\n"
        "   hardware vendor prefix (e.g. D4:BE:D9 for Dell).\n"
        "4. Set  ethernet0.addressType = \"static\"\n"
        "5. Save and start the VM."},

       {"Method 2: Change MAC address in VirtualBox",
        "1. Shut down the VM.\n"
        "2. Open a terminal or command prompt.\n"
        "3. Run:  VBoxManage modifyvm \"VM Name\"\n"
        "         --macaddress1 D4BED9112233\n"
        "   (replace D4BED9112233 with a real-vendor prefix + random bytes).\n"
        "4. Start the VM."},

       {"Method 3: Change MAC address from inside the VM",
        "1. Open Device Manager (Windows) or ip link (Linux).\n"
        "2. Find your network adapter properties.\n"
        "3. Set a custom MAC address using a real-vendor prefix.\n"
        "4. Restart the network adapter or reboot."},

       {NULL, NULL}
     },
     {
       /* VMware */  {
           "ethernet0.addressType = \"static\"\n"
           "ethernet0.address = \"D4:BE:D9:XX:XX:XX\"",
           NULL},
       /* VBox   */  {"VBoxManage modifyvm \"<VM>\" --macaddress1 D4BED9112233", NULL},
       /* KVM    */  {"-netdev user,id=net0,mac=D4:BE:D9:XX:XX:XX", NULL},
       /* HyperV */  {"Set-VMNetworkAdapter -VMName \"<VM>\" -StaticMacAddress \"D4BED9112233\"", NULL}
     }
    },

    /* ---- Virtual driver check ---- */
    {"Virtual driver check",
     "VM guest-tool drivers or services were found running, which reveals the\n"
     "presence of a hypervisor.",
     3,
     {
       {"Method 1: Uninstall guest tools",
        "1. Open Settings > Apps (Windows) or your package manager (Linux).\n"
        "2. Find \"VMware Tools\", \"VirtualBox Guest Additions\", or\n"
        "   \"Hyper-V Integration Services\".\n"
        "3. Click Uninstall and follow the prompts.\n"
        "4. Reboot the VM."},

       {"Method 2: Disable guest-tool services",
        "1. Open Services (services.msc) on Windows.\n"
        "2. Find services like \"VMware Tools\", \"VBoxService\", etc.\n"
        "3. Right-click > Properties > set Startup type to Disabled.\n"
        "4. Click Stop, then OK.\n"
        "5. Reboot to confirm the services stay disabled."},

       {"Method 3: Rename or remove driver files",
        "1. Open an Administrator command prompt.\n"
        "2. Navigate to C:\\Windows\\System32\\drivers\\\n"
        "3. Rename known VM drivers (e.g. rename vm3dmp.sys to vm3dmp.sys.bak).\n"
        "4. Reboot the VM."},

       {NULL, NULL}
     },
     {
       /* VMware */  {NULL, "Uninstall VMware Tools from Settings > Apps, then reboot."},
       /* VBox   */  {NULL, "Uninstall VirtualBox Guest Additions from Settings > Apps, then reboot."},
       /* KVM    */  {NULL, "Remove spice-vdagent / qemu-guest-agent via your package manager, then reboot."},
       /* HyperV */  {NULL, "Disable Hyper-V Integration Services in Settings > Apps > Optional features."}
     }
    },

    /* ---- Registry artefact check ---- */
    {"Registry artefact check",
     "Windows registry keys were found that reference virtualisation software,\n"
     "making it easy to identify this as a virtual machine.",
     3,
     {
       {"Method 1: Delete VM-related registry keys",
        "1. Open Registry Editor (regedit) as Administrator.\n"
        "2. Navigate to HKLM\\SOFTWARE and look for keys like\n"
        "   \"VMware, Inc.\", \"Oracle\\VirtualBox Guest Additions\", etc.\n"
        "3. Right-click the key and choose Delete.\n"
        "4. Reboot the VM."},

       {"Method 2: Rename registry keys instead of deleting",
        "1. Open Registry Editor (regedit) as Administrator.\n"
        "2. Find the VM-related key (e.g. HKLM\\SOFTWARE\\VMware, Inc.).\n"
        "3. Right-click > Rename, and add a prefix like \"_disabled_\".\n"
        "4. This keeps the data available if you need to restore it later."},

       {"Method 3: Use a registry cleaning script",
        "1. Create a .reg file with the keys you want to remove.\n"
        "2. Example content:\n"
        "   Windows Registry Editor Version 5.00\n"
        "   [-HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware, Inc.]\n"
        "3. Double-click the .reg file to apply.\n"
        "4. Reboot the VM."},

       {NULL, NULL}
     },
     {
       /* VMware */  {NULL,
           "Open regedit as Admin and delete:\n"
           "  HKLM\\SOFTWARE\\VMware, Inc.\n"
           "  HKLM\\SOFTWARE\\Classes\\Installer\\..\\VMware*\n"
           "Then reboot."},
       /* VBox   */  {NULL,
           "Open regedit as Admin and delete:\n"
           "  HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions\n"
           "Then reboot."},
       /* KVM    */  {NULL,
           "Open regedit as Admin and delete any keys referencing\n"
           "\"QEMU\", \"Virtio\", or \"Red Hat\". Then reboot."},
       /* HyperV */  {NULL,
           "Open regedit as Admin and delete any keys referencing\n"
           "\"Hyper-V\" or \"Microsoft Virtual\". Then reboot."}
     }
    },

    /* ---- Filesystem artefact check ---- */
    {"Filesystem artefact check",
     "Files belonging to virtualisation software were found on disk, which can\n"
     "be used to detect the virtual machine.",
     3,
     {
       {"Method 1: Delete VM-specific files",
        "1. Open an Administrator command prompt.\n"
        "2. Delete known VM files, for example:\n"
        "   del C:\\Windows\\System32\\drivers\\vm*.sys\n"
        "   del C:\\Windows\\System32\\vbox*.dll\n"
        "3. Reboot the VM."},

       {"Method 2: Rename VM files instead of deleting",
        "1. Open an Administrator command prompt.\n"
        "2. Rename files so they are not found by detection tools:\n"
        "   ren C:\\Windows\\System32\\drivers\\vmhgfs.sys vmhgfs.sys.bak\n"
        "3. This lets you restore them later if needed.\n"
        "4. Reboot the VM."},

       {"Method 3: Uninstall guest tools (removes files automatically)",
        "1. Open Settings > Apps.\n"
        "2. Find \"VMware Tools\" or \"VirtualBox Guest Additions\".\n"
        "3. Click Uninstall -- this removes most VM-specific files.\n"
        "4. Manually check for leftover files and delete them.\n"
        "5. Reboot."},

       {NULL, NULL}
     },
     {
       /* VMware */  {NULL,
           "Delete or rename in an Admin command prompt:\n"
           "  del C:\\Windows\\System32\\drivers\\vm*.sys\n"
           "  del C:\\Windows\\System32\\vm*.dll\n"
           "Then reboot."},
       /* VBox   */  {NULL,
           "Delete or rename in an Admin command prompt:\n"
           "  del C:\\Windows\\System32\\drivers\\VBox*.sys\n"
           "  del C:\\Windows\\System32\\VBox*.dll\n"
           "Then reboot."},
       /* KVM    */  {NULL,
           "Delete or rename in an Admin command prompt:\n"
           "  del C:\\Windows\\System32\\drivers\\virtio*.sys\n"
           "  del C:\\Windows\\System32\\drivers\\vio*.sys\n"
           "Then reboot."},
       /* HyperV */  {NULL,
           "Delete or rename in an Admin command prompt:\n"
           "  del C:\\Windows\\System32\\drivers\\vmbus.sys\n"
           "  del C:\\Windows\\System32\\drivers\\storvsc.sys\n"
           "Then reboot."}
     }
    },

    /* ---- Timing (sleep acceleration) ---- */
    {"Timing (sleep acceleration)",
     "A timed sleep finished much faster than expected, which suggests the\n"
     "hypervisor is accelerating time to speed up the VM.",
     3,
     {
       {"Method 1: Disable time acceleration in VMware",
        "1. Shut down the VM.\n"
        "2. Open the .vmx file in a text editor.\n"
        "3. Add:  monitor_control.virtual_rdtsc = \"TRUE\"\n"
        "4. Also add:  tools.syncTime = \"FALSE\"\n"
        "5. Save and start the VM."},

       {"Method 2: Adjust KVM / QEMU clock settings",
        "1. Add  -rtc base=utc,clock=host  to your QEMU command.\n"
        "2. Ensure the guest clock source is set to TSC:\n"
        "   echo tsc > /sys/devices/system/clocksource/clocksource0/current_clocksource\n"
        "3. Start the VM."},

       {"Method 3: Allocate more CPU resources",
        "1. Increase the number of vCPUs assigned to the VM.\n"
        "2. Ensure the host is not overcommitting CPU resources.\n"
        "3. Pin vCPUs to physical cores to reduce scheduling delays.\n"
        "4. Restart the VM."},

       {NULL, NULL}
     },
     {
       /* VMware */  {
           "monitor_control.virtual_rdtsc = \"TRUE\"\n"
           "tools.syncTime = \"FALSE\"",
           NULL},
       /* VBox   */  {
           "VBoxManage setextradata \"<VM>\" \"VBoxInternal/TM/TSCTiedToExecution\" 1",
           NULL},
       /* KVM    */  {"-rtc base=utc,clock=host", NULL},
       /* HyperV */  {"Set-VMProcessor -VMName \"<VM>\" -ExposeVirtualizationExtensions $false", NULL}
     }
    },

    /* ---- Timing (RDTSC consistency) ---- */
    {"Timing (RDTSC consistency)",
     "The CPU timestamp counter (RDTSC) showed an unusually large gap,\n"
     "which is a common sign of hypervisor interception.",
     3,
     {
       {"Method 1: Enable TSC passthrough in VMware",
        "1. Shut down the VM.\n"
        "2. Open the .vmx file in a text editor.\n"
        "3. Add:  monitor_control.virtual_rdtsc = \"TRUE\"\n"
        "4. Save and start the VM."},

       {"Method 2: Use TSC-related CPU flags in KVM",
        "1. Add the invtsc or tsc=reliable flag to your QEMU -cpu option:\n"
        "   -cpu host,+invtsc\n"
        "2. Pin vCPUs to physical cores to reduce TSC drift.\n"
        "3. Start the VM."},

       {"Method 3: Pin vCPUs and reduce host load",
        "1. Pin each vCPU to a dedicated physical CPU core.\n"
        "   VMware: processor0.use = \"TRUE\", sched.cpu.affinity = \"0\"\n"
        "   KVM: use taskset or cgroup cpuset to pin QEMU threads.\n"
        "2. Stop unnecessary host processes to reduce jitter.\n"
        "3. Restart the VM."},

       {NULL, NULL}
     },
     {
       /* VMware */  {"monitor_control.virtual_rdtsc = \"TRUE\"", NULL},
       /* VBox   */  {
           "VBoxManage setextradata \"<VM>\" \"VBoxInternal/TM/TSCTiedToExecution\" 1",
           NULL},
       /* KVM    */  {"-cpu host,+invtsc", NULL},
       /* HyperV */  {NULL, "Pin vCPUs and ensure adequate CPU allocation."}
     }
    },

    /* ---- Timing (loop jitter) ---- */
    {"Timing (loop jitter)",
     "A tight timing loop showed high variation (jitter), which suggests the\n"
     "hypervisor is interrupting the VM to service other tasks.",
     3,
     {
       {"Method 1: Pin vCPUs to physical cores",
        "1. In VMware: set  sched.cpu.affinity  in the .vmx file.\n"
        "2. In KVM: use  taskset  or cgroup cpuset on the QEMU process.\n"
        "3. In Hyper-V: use  Set-VMProcessor -Reserve  to guarantee CPU.\n"
        "4. Restart the VM."},

       {"Method 2: Increase VM CPU priority",
        "1. In VMware: set  sched.cpu.shares = \"high\"  in the .vmx.\n"
        "2. In KVM: use  chrt -r 99  on the QEMU process for real-time priority.\n"
        "3. Ensure no other VMs are competing for the same CPU cores.\n"
        "4. Restart the VM."},

       {"Method 3: Reduce host background activity",
        "1. Close unnecessary applications on the host.\n"
        "2. Disable host antivirus real-time scanning during the test.\n"
        "3. Stop any other running VMs to free CPU resources.\n"
        "4. Rerun the scan."},

       {NULL, NULL}
     },
     {
       /* VMware */  {
           "sched.cpu.affinity = \"0\"\n"
           "sched.cpu.shares = \"high\"",
           NULL},
       /* VBox   */  {NULL, "Pin vCPUs: use processor affinity in VBox settings and close other VMs."},
       /* KVM    */  {NULL, "Run:  taskset -c 0 <qemu-pid>  and  chrt -r 99 <qemu-pid>"},
       /* HyperV */  {"Set-VMProcessor -VMName \"<VM>\" -Reserve 100", NULL}
     }
    },

    /* ---- CPUID hypervisor bit ---- */
    {"CPUID hypervisor bit",
     "The CPU reports a hypervisor presence bit (CPUID leaf 1, ECX bit 31),\n"
     "which is a direct indicator of virtualisation.",
     4,
     {
       {"Method 1: Mask the hypervisor bit in VMware",
        "1. Shut down the VM.\n"
        "2. Open the .vmx file in a text editor.\n"
        "3. Add:  cpuid.1.ecx = \"0---:----:----:----:----:----:----:----\"\n"
        "4. Save and start the VM."},

       {"Method 2: Hide hypervisor from KVM/QEMU guest",
        "1. Add  -cpu host,-hypervisor  to your QEMU launch command.\n"
        "2. This clears the hypervisor bit so the guest sees a bare-metal CPU.\n"
        "3. Start the VM."},

       {"Method 3: Disable paravirtualisation in VirtualBox",
        "1. Shut down the VM.\n"
        "2. Run:  VBoxManage modifyvm \"VM Name\" --paravirtprovider none\n"
        "3. Start the VM.\n"
        "4. Verify with a CPUID tool inside the guest."},

       {"Method 4: Use Hyper-V enlightenments selectively",
        "1. In Hyper-V Manager, open VM Settings.\n"
        "2. Under Integration Services, disable items you do not need.\n"
        "3. For QEMU with Hyper-V passthrough, avoid  -cpu host,hv_vendor_id.\n"
        "4. Restart the VM."}
     },
     {
       /* VMware */  {"cpuid.1.ecx = \"0---:----:----:----:----:----:----:----\"", NULL},
       /* VBox   */  {"VBoxManage modifyvm \"<VM>\" --paravirtprovider none", NULL},
       /* KVM    */  {"-cpu host,-hypervisor", NULL},
       /* HyperV */  {NULL, "Disable unneeded Integration Services in Hyper-V Manager > VM Settings."}
     }
    },

    /* ---- VMware backdoor I/O port ---- */
    {"VMware backdoor I/O port",
     "The VMware backdoor I/O port (0x5658) responded, confirming this\n"
     "is a VMware virtual machine.",
     3,
     {
       {"Method 1: Disable VMware backdoor in .vmx",
        "1. Shut down the VM.\n"
        "2. Open the .vmx file in a text editor.\n"
        "3. Add these lines:\n"
        "   isolation.tools.getPtrLocation.disable = \"TRUE\"\n"
        "   isolation.tools.setPtrLocation.disable = \"TRUE\"\n"
        "   isolation.tools.setVersion.disable = \"TRUE\"\n"
        "   isolation.tools.getVersion.disable = \"TRUE\"\n"
        "4. Save and start the VM."},

       {"Method 2: Uninstall VMware Tools",
        "1. Open Settings > Apps inside the VM.\n"
        "2. Find \"VMware Tools\" and click Uninstall.\n"
        "3. Reboot the VM.\n"
        "4. The backdoor port may still respond, but most communication\n"
        "   channels will be closed."},

       {"Method 3: Switch to a different hypervisor",
        "1. Export your VM to OVA format (File > Export in VMware).\n"
        "2. Import the OVA into VirtualBox, Hyper-V, or KVM.\n"
        "3. These hypervisors do not use the VMware backdoor port.\n"
        "4. Verify by re-running the scan."},

       {NULL, NULL}
     },
     {
       /* VMware */  {
           "isolation.tools.getPtrLocation.disable = \"TRUE\"\n"
           "isolation.tools.setPtrLocation.disable = \"TRUE\"\n"
           "isolation.tools.setVersion.disable = \"TRUE\"\n"
           "isolation.tools.getVersion.disable = \"TRUE\"",
           NULL},
       /* VBox   */  {NULL, NULL},  /* N/A -- VirtualBox-specific port does not exist */
       /* KVM    */  {NULL, NULL},  /* N/A */
       /* HyperV */  {NULL, NULL}   /* N/A */
     }
    },

    /* ---- Debugger checks ---- */
    {"Debugger checks",
     "A debugger was detected attached to this process, which could indicate\n"
     "analysis or reverse-engineering activity.",
     3,
     {
       {"Method 1: Close all debuggers",
        "1. Close Visual Studio, x64dbg, WinDbg, OllyDbg, or any other debugger.\n"
        "2. Check Task Manager for debugger processes still running.\n"
        "3. End any debugger processes you find.\n"
        "4. Re-run the scan."},

       {"Method 2: Detach remote debuggers",
        "1. If using remote debugging, disconnect the remote debugger session.\n"
        "2. Disable the remote debugging service:\n"
        "   net stop msvsmon  (for Visual Studio Remote Debugger)\n"
        "3. Re-run the scan."},

       {"Method 3: Check for kernel debuggers",
        "1. Open an Administrator command prompt.\n"
        "2. Run:  bcdedit /debug off\n"
        "3. Run:  bcdedit /set testsigning off\n"
        "4. Reboot the machine.\n"
        "5. Re-run the scan."},

       {NULL, NULL}
     },
     {
       /* VMware */  {NULL,
           "Close all debuggers, then run as Admin:\n"
           "  bcdedit /debug off\n"
           "  bcdedit /set testsigning off\n"
           "Reboot and re-run the scan."},
       /* VBox   */  {NULL,
           "Close all debuggers, then run as Admin:\n"
           "  bcdedit /debug off\n"
           "  bcdedit /set testsigning off\n"
           "Reboot and re-run the scan."},
       /* KVM    */  {NULL,
           "Close all debuggers, then run as Admin:\n"
           "  bcdedit /debug off\n"
           "  bcdedit /set testsigning off\n"
           "Reboot and re-run the scan."},
       /* HyperV */  {NULL,
           "Close all debuggers, then run as Admin:\n"
           "  bcdedit /debug off\n"
           "  bcdedit /set testsigning off\n"
           "Reboot and re-run the scan."}
     }
    },

    /* sentinel */
    {NULL, NULL, 0,
     {{NULL, NULL}, {NULL, NULL}, {NULL, NULL}, {NULL, NULL}},
     {{NULL, NULL}, {NULL, NULL}, {NULL, NULL}, {NULL, NULL}}
    }
};

const check_tip *tip_for_check(const char *label) {
    if (!label) return NULL;
    for (int i = 0; g_tips[i].label; i++) {
        if (strcmp(label, g_tips[i].label) == 0)
            return &g_tips[i];
    }
    return NULL;
}
