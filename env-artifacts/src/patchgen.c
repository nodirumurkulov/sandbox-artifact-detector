#include "patchgen.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  include <direct.h>
#else
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

static const char *platform_file_ext(hypervisor_platform p) {
    switch (p) {
        case PLATFORM_VMWARE: return ".vmx";
        case PLATFORM_VBOX:   return ".sh";
        case PLATFORM_KVM:    return ".xml";
        case PLATFORM_HYPERV: return ".ps1";
        default:              return ".txt";
    }
}

static const char *platform_label(hypervisor_platform p) {
    switch (p) {
        case PLATFORM_VMWARE: return "VMware";
        case PLATFORM_VBOX:   return "VirtualBox";
        case PLATFORM_KVM:    return "KVM / QEMU";
        case PLATFORM_HYPERV: return "Hyper-V";
        default:              return "Unknown";
    }
}

static const char *platform_comment_prefix(hypervisor_platform p) {
    switch (p) {
        case PLATFORM_VMWARE: return "#";
        case PLATFORM_VBOX:   return "#";
        case PLATFORM_KVM:    return "<!--";
        case PLATFORM_HYPERV: return "#";
        default:              return "#";
    }
}

static const char *platform_comment_suffix(hypervisor_platform p) {
    if (p == PLATFORM_KVM) return " -->";
    return "";
}

/* ------------------------------------------------------------------ */
/*  Core writer                                                        */
/* ------------------------------------------------------------------ */

void patchgen_write(const scan_snapshot *snap,
                    hypervisor_platform platform,
                    FILE *fp) {
    char ts[32];
    {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
    }

    const char *cp = platform_comment_prefix(platform);
    const char *cs = platform_comment_suffix(platform);

    /* Header */
    fprintf(fp, "%s ============================================== %s\n", cp, cs);
    fprintf(fp, "%s ENV-Artifact Detector v1.1.0 - Host Config Patch %s\n", cp, cs);
    fprintf(fp, "%s Platform:  %s %s\n", cp, platform_label(platform), cs);
    fprintf(fp, "%s Generated: %s %s\n", cp, ts, cs);
    fprintf(fp, "%s %s\n", cp, cs);
    fprintf(fp, "%s Replace <YOUR_VM_NAME> with your actual VM name. %s\n", cp, cs);
    fprintf(fp, "%s ============================================== %s\n\n", cp, cs);

    /* Platform-specific wrapper start */
    if (platform == PLATFORM_VBOX) {
        fprintf(fp, "#!/bin/bash\n");
        fprintf(fp, "# VBoxManage commands to harden VM\n");
        fprintf(fp, "VM=\"<YOUR_VM_NAME>\"\n\n");
    } else if (platform == PLATFORM_HYPERV) {
        fprintf(fp, "# PowerShell script to harden Hyper-V VM\n");
        fprintf(fp, "$VM = \"<YOUR_VM_NAME>\"\n\n");
    } else if (platform == PLATFORM_KVM) {
        fprintf(fp, "<!-- Add these elements to your libvirt XML domain config -->\n");
        fprintf(fp, "<!-- Or use the QEMU flags shown as comments -->\n\n");
    }

    int line_count = 0;

    /* Iterate over failed checks and emit config lines */
    for (int i = 0; i < snap->num_checks; i++) {
        if (snap->results[i].status != CHECK_FAILED) continue;

        const check_tip *tip = tip_for_check(snap->results[i].label);
        if (!tip) continue;

        const platform_fix *fix = &tip->platforms[platform];
        if (!fix->config_lines) continue;

        /* Section header for this check */
        fprintf(fp, "%s --- %s --- %s\n", cp, tip->label, cs);

        /* Emit the config lines, adjusting VM name placeholder */
        const char *p = fix->config_lines;
        while (*p) {
            /* Copy line by line */
            const char *eol = strchr(p, '\n');
            if (!eol) eol = p + strlen(p);

            /* Write the line, replacing <VM> with platform-specific placeholder */
            for (const char *c = p; c < eol; c++) {
                if (strncmp(c, "\"<VM>\"", 6) == 0) {
                    if (platform == PLATFORM_VBOX)
                        fprintf(fp, "\"$VM\"");
                    else if (platform == PLATFORM_HYPERV)
                        fprintf(fp, "\"$VM\"");
                    else
                        fprintf(fp, "\"<YOUR_VM_NAME>\"");
                    c += 5; /* skip past <VM>" (loop will ++ past closing ") */
                } else {
                    fputc(*c, fp);
                }
            }
            fputc('\n', fp);
            line_count++;

            if (*eol == '\n') p = eol + 1;
            else break;
        }
        fprintf(fp, "\n");
    }

    if (line_count == 0) {
        fprintf(fp, "%s No host-side configuration changes needed. %s\n", cp, cs);
        fprintf(fp, "%s All failed checks require guest-side fixes only. %s\n", cp, cs);
    }

    /* Footer */
    fprintf(fp, "\n%s ============================================== %s\n", cp, cs);
    fprintf(fp, "%s End of patch file %s\n", cp, cs);
    fprintf(fp, "%s ============================================== %s\n", cp, cs);
}

/* ------------------------------------------------------------------ */
/*  Generate to file                                                   */
/* ------------------------------------------------------------------ */

int patchgen_generate(const scan_snapshot *snap,
                      hypervisor_platform platform,
                      char *out_path, size_t out_path_size) {
    ensure_logs_dir();

    char ts[32];
    {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        strftime(ts, sizeof(ts), "%Y-%m-%d_%H-%M-%S", t);
    }

    snprintf(out_path, out_path_size, "logs/patch_%s%s",
             ts, platform_file_ext(platform));

    FILE *fp = fopen(out_path, "w");
    if (!fp) {
        fprintf(stderr, "patchgen: cannot create %s\n", out_path);
        return -1;
    }

    patchgen_write(snap, platform, fp);
    fclose(fp);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Preview to stdout                                                  */
/* ------------------------------------------------------------------ */

void patchgen_preview(const scan_snapshot *snap,
                      hypervisor_platform platform) {
    printf("\n");
    patchgen_write(snap, platform, stdout);
}
