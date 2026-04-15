#include "interactive.h"
#include "tips.h"
#include "remediate.h"
#include "rollback.h"
#include "profiles.h"
#include "patchgen.h"
#include "compare.h"
#include "agent.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
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

static void html_escape(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j + 1 < dst_size; ++i) {
        const char *esc = NULL;
        size_t esc_len = 0;
        switch (src[i]) {
            case '&':  esc = "&amp;";  esc_len = 5; break;
            case '<':  esc = "&lt;";   esc_len = 4; break;
            case '>':  esc = "&gt;";   esc_len = 4; break;
            case '"':  esc = "&quot;"; esc_len = 6; break;
            default: break;
        }
        if (esc) {
            if (j + esc_len >= dst_size) break;
            memcpy(dst + j, esc, esc_len);
            j += esc_len;
        } else {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

/* Write an html-escaped string directly to a FILE. */
static void fprint_escaped(FILE *f, const char *s) {
    char buf[1024];
    html_escape(s, buf, sizeof(buf));
    fputs(buf, f);
}

static const char *status_str(check_status st) {
    switch (st) {
        case CHECK_PASSED: return "PASSED";
        case CHECK_FAILED: return "FAILED";
        case CHECK_ERROR:  return "ERROR";
        default:           return "UNKNOWN";
    }
}

/* Print a multi-line string with a given indent prefix on each line. */
static void print_indented(const char *text, const char *indent) {
    if (!text) return;
    const char *p = text;
    while (*p) {
        printf("%s", indent);
        while (*p && *p != '\n') {
            putchar(*p);
            p++;
        }
        putchar('\n');
        if (*p == '\n') p++;
    }
}

/* ------------------------------------------------------------------ */
/*  show_detailed_data                                                 */
/* ------------------------------------------------------------------ */

void show_detailed_data(const scan_snapshot *snap) {
    printf("\n");
    printf("==============================================\n");
    printf("  DETAILED SCAN DATA\n");
    printf("==============================================\n");

    /* BIOS */
    printf("\n  --- BIOS ---\n");
    printf("  Vendor  : %s\n", snap->bios.vendor[0]  ? snap->bios.vendor  : "(empty)");
    printf("  Version : %s\n", snap->bios.version[0]  ? snap->bios.version  : "(empty)");
    printf("  Product : %s\n", snap->bios.product[0]  ? snap->bios.product  : "(empty)");

    /* MAC */
    printf("\n  --- MAC Address ---\n");
    printf("  Address : %s\n", snap->mac.address[0] ? snap->mac.address : "(empty)");
    printf("  Vendor  : %s\n", snap->mac.vendor[0]  ? snap->mac.vendor  : "(empty)");

    /* Drivers */
    printf("\n  --- Virtual Drivers (%d detected) ---\n", snap->driver_count);
    if (snap->driver_count == 0) {
        printf("  (none)\n");
    } else {
        for (int i = 0; i < snap->driver_count; i++) {
            printf("  [%d] %s  (vendor: %s, loaded: %s)\n",
                   i + 1,
                   snap->drivers[i].name,
                   snap->drivers[i].vendor[0] ? snap->drivers[i].vendor : "-",
                   snap->drivers[i].loaded ? "yes" : "no");
        }
    }

    /* Registry */
    printf("\n  --- Registry Artefacts (%d detected) ---\n", snap->reg_count);
    if (snap->reg_count == 0) {
        printf("  (none)\n");
    } else {
        for (int i = 0; i < snap->reg_count; i++) {
            printf("  [%d] %s\n      %s\n",
                   i + 1,
                   snap->reg_hits[i].path,
                   snap->reg_hits[i].description);
        }
    }

    /* Filesystem */
    printf("\n  --- Filesystem Artefacts (%d detected) ---\n", snap->fs_count);
    if (snap->fs_count == 0) {
        printf("  (none)\n");
    } else {
        for (int i = 0; i < snap->fs_count; i++) {
            printf("  [%d] %s\n      %s\n",
                   i + 1,
                   snap->fs_hits[i].path,
                   snap->fs_hits[i].description);
        }
    }

    /* Timing */
    printf("\n  --- Timing ---\n");
    printf("  Sleep actual  : %" PRIu64 " ms\n", snap->timing.sleep_ms_actual);
    printf("  RDTSC delta   : %" PRIu64 "\n",    snap->timing.rdtsc_delta);
    printf("  Loop median   : %.3f ms\n",         snap->timing.loop.median_ms);
    printf("  Loop P95      : %.3f ms\n",         snap->timing.loop.p95_ms);
    printf("  Loop min/max  : %.3f / %.3f ms\n",  snap->timing.loop.min_ms,
                                                    snap->timing.loop.max_ms);
    printf("  Loop samples  : %d\n",              snap->timing.loop.samples);

    /* CPUID */
    printf("\n  --- CPUID ---\n");
    printf("  Architecture  : %s\n",   snap->cpuid.arch);
    printf("  Supported     : %s\n",   snap->cpuid.supported ? "yes" : "no");
    printf("  Leaf 1 ECX    : 0x%08X\n", (unsigned)snap->cpuid.leaf_1_ecx);
    printf("  Hypervisor bit: %s\n",   snap->cpuid.hypervisor_bit ? "SET" : "clear");

    /* VMware backdoor */
    printf("\n  --- VMware Backdoor ---\n");
    printf("  Supported     : %s\n", snap->vmware.supported ? "yes" : "no");
    printf("  Detected      : %s\n", snap->vmware.detected  ? "yes" : "no");

#ifdef _WIN32
    /* Debugger */
    printf("\n  --- Debugger ---\n");
    printf("  IsDebuggerPresent      : %s\n", snap->debugger.is_debugger_present    ? "yes" : "no");
    printf("  RemoteDebuggerPresent  : %s\n", snap->debugger.remote_debugger_present ? "yes" : "no");
    printf("  PEB->BeingDebugged     : %s\n", snap->debugger.peb_being_debugged      ? "yes" : "no");
    printf("  ProcessDebugPort       : %s (detected: %s)\n",
           snap->debugger.process_debug_port.supported   ? "supported" : "N/A",
           snap->debugger.process_debug_port.detected    ? "yes" : "no");
    printf("  ProcessDebugFlags      : %s (detected: %s)\n",
           snap->debugger.process_debug_flags.supported  ? "supported" : "N/A",
           snap->debugger.process_debug_flags.detected   ? "yes" : "no");
    printf("  ProcessDebugObject     : %s (detected: %s)\n",
           snap->debugger.process_debug_object.supported ? "supported" : "N/A",
           snap->debugger.process_debug_object.detected  ? "yes" : "no");
#endif

    printf("\n==============================================\n");
}

/* ------------------------------------------------------------------ */
/*  show_recommendations                                               */
/* ------------------------------------------------------------------ */

void show_recommendations(const scan_snapshot *snap) {
    printf("\n");
    printf("==============================================\n");
    printf("  HARDENING RECOMMENDATIONS\n");
    printf("==============================================\n");

    int any = 0;
    for (int i = 0; i < snap->num_checks; i++) {
        if (snap->results[i].status != CHECK_FAILED) continue;
        const check_tip *tip = tip_for_check(snap->results[i].label);
        if (!tip) continue;
        any = 1;

        printf("\n  ----------------------------------------------\n");
        printf("  [!] %s\n", snap->results[i].label);
        printf("      ");
        print_indented(tip->summary, "      ");
        printf("\n");

        for (int m = 0; m < tip->num_methods; m++) {
            if (!tip->methods[m].title) break;
            printf("      %s\n", tip->methods[m].title);
            print_indented(tip->methods[m].steps, "        ");
            printf("\n");
        }
    }

    if (!any) {
        printf("\n  All checks passed -- no remediation needed.\n");
    }

    printf("==============================================\n");
}

/* ------------------------------------------------------------------ */
/*  show_fix_guide — interactive step-by-step walkthrough              */
/* ------------------------------------------------------------------ */

void show_fix_guide(const scan_snapshot *snap) {
    /* Collect failed checks that have tips */
    int failed_idx[SNAP_MAX_CHECKS];
    int failed_count = 0;

    for (int i = 0; i < snap->num_checks; i++) {
        if (snap->results[i].status != CHECK_FAILED) continue;
        if (!tip_for_check(snap->results[i].label)) continue;
        failed_idx[failed_count++] = i;
    }

    if (failed_count == 0) {
        printf("\n  All checks passed -- nothing to fix!\n");
        return;
    }

    char line[64];

    for (;;) {
        printf("\n");
        printf("==============================================\n");
        printf("  STEP-BY-STEP FIX GUIDE\n");
        printf("==============================================\n");
        printf("  Select a failed check to see fix methods:\n\n");

        for (int i = 0; i < failed_count; i++) {
            printf("  %d  %s\n", i + 1, snap->results[failed_idx[i]].label);
        }
        printf("  0  Back to main menu\n");
        printf("==============================================\n");
        printf("  Choice: ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin))
            return;

        int choice;
        if (sscanf(line, "%d", &choice) != 1)
            continue;

        if (choice == 0) return;
        if (choice < 1 || choice > failed_count) {
            printf("  Invalid choice.\n");
            continue;
        }

        int idx = failed_idx[choice - 1];
        const check_tip *tip = tip_for_check(snap->results[idx].label);
        if (!tip) continue;

        printf("\n");
        printf("  ==============================================\n");
        printf("  FIX: %s\n", tip->label);
        printf("  ==============================================\n");
        printf("\n  What was detected:\n");
        printf("  ");
        print_indented(tip->summary, "  ");
        printf("\n");

        for (int m = 0; m < tip->num_methods; m++) {
            if (!tip->methods[m].title) break;
            printf("  --- %s ---\n", tip->methods[m].title);
            print_indented(tip->methods[m].steps, "    ");
            printf("\n");
        }

        printf("  Press Enter to continue...");
        fflush(stdout);
        fgets(line, sizeof(line), stdin);
    }
}

/* ------------------------------------------------------------------ */
/*  show_evasion_playbook — consolidated platform-specific guide       */
/* ------------------------------------------------------------------ */

static const char *platform_names[PLATFORM_COUNT] = {
    "VMware", "VirtualBox", "KVM / QEMU", "Hyper-V"
};

static const char *platform_config_label[PLATFORM_COUNT] = {
    "Add these lines to your .vmx config file",
    "Run these VBoxManage commands on the host",
    "Add these flags to your QEMU launch command",
    "Run these PowerShell commands on the host"
};

void show_evasion_playbook(const scan_snapshot *snap) {
    /* Collect failed checks that have tips */
    int failed_idx[SNAP_MAX_CHECKS];
    int failed_count = 0;

    for (int i = 0; i < snap->num_checks; i++) {
        if (snap->results[i].status != CHECK_FAILED) continue;
        if (!tip_for_check(snap->results[i].label)) continue;
        failed_idx[failed_count++] = i;
    }

    if (failed_count == 0) {
        printf("\n  All checks passed -- nothing to fix!\n");
        return;
    }

    char line[64];
    int choice;

    /* Platform selection */
    printf("\n");
    printf("==============================================\n");
    printf("  EVASION PLAYBOOK\n");
    printf("==============================================\n");
    printf("  Which hypervisor are you using?\n\n");
    printf("  1  VMware\n");
    printf("  2  VirtualBox\n");
    printf("  3  KVM / QEMU\n");
    printf("  4  Hyper-V\n");
    printf("  0  Back to main menu\n");
    printf("==============================================\n");
    printf("  Choice: ");
    fflush(stdout);

    if (!fgets(line, sizeof(line), stdin)) return;
    if (sscanf(line, "%d", &choice) != 1 || choice < 0 || choice > 4) {
        printf("  Invalid choice.\n");
        return;
    }
    if (choice == 0) return;

    hypervisor_platform plat = (hypervisor_platform)(choice - 1);

    /* Collect config lines and guest steps for the chosen platform */
    const char *config_items[SNAP_MAX_CHECKS];
    const char *config_labels[SNAP_MAX_CHECKS];
    int config_count = 0;

    const char *guest_items[SNAP_MAX_CHECKS];
    const char *guest_labels[SNAP_MAX_CHECKS];
    int guest_count = 0;

    for (int i = 0; i < failed_count; i++) {
        const check_tip *tip = tip_for_check(snap->results[failed_idx[i]].label);
        if (!tip) continue;
        const platform_fix *fix = &tip->platforms[plat];
        if (fix->config_lines) {
            config_labels[config_count] = tip->label;
            config_items[config_count]  = fix->config_lines;
            config_count++;
        }
        if (fix->guest_steps) {
            guest_labels[guest_count] = tip->label;
            guest_items[guest_count]  = fix->guest_steps;
            guest_count++;
        }
    }

    /* Print the consolidated playbook */
    printf("\n");
    printf("  ==============================================\n");
    printf("  EVASION PLAYBOOK -- %s\n", platform_names[plat]);
    printf("  ==============================================\n");
    printf("  You have %d failed check(s) to address.\n", failed_count);

    int step = 1;

    /* Phase 1: Shut down */
    if (config_count > 0) {
        printf("\n  ---- STEP %d: Shut down the VM ----\n", step++);
        printf("    Power off the virtual machine completely.\n");

        /* Phase 2: Host-side config */
        printf("\n  ---- STEP %d: %s ----\n", step++, platform_config_label[plat]);
        for (int i = 0; i < config_count; i++) {
            printf("\n    # %s\n", config_labels[i]);
            print_indented(config_items[i], "    ");
        }
    }

    /* Phase 3: Start + guest-side actions */
    if (guest_count > 0) {
        if (config_count > 0) {
            printf("\n  ---- STEP %d: Save, start the VM ----\n", step++);
            printf("    Save any config changes and boot the VM.\n");
        }

        printf("\n  ---- STEP %d: Inside the VM (as Administrator) ----\n", step++);
        for (int i = 0; i < guest_count; i++) {
            printf("\n    # %s\n", guest_labels[i]);
            print_indented(guest_items[i], "    ");
        }
    }

    /* Phase 4: Reboot + verify */
    printf("\n  ---- STEP %d: Reboot and verify ----\n", step++);
    printf("    Reboot the VM and re-run the detector to check results.\n");

    if (config_count == 0 && guest_count == 0) {
        printf("\n  Note: No platform-specific fixes available for %s\n",
               platform_names[plat]);
        printf("  for the current failed checks. Use option 5 (fix guide)\n");
        printf("  for general methods.\n");
    }

    printf("\n  ==============================================\n");
}

/* ------------------------------------------------------------------ */
/*  export_html_report                                                 */
/* ------------------------------------------------------------------ */

int export_html_report(const scan_snapshot *snap) {
    /* Write to a temp file and open in the default browser.
       The user can save the page from the browser if they want. */
    char filename[512];
#ifdef _WIN32
    {
        char tmp_dir[MAX_PATH];
        GetTempPathA(MAX_PATH, tmp_dir);
        snprintf(filename, sizeof(filename),
                 "%senv_artifacts_report.html", tmp_dir);
    }
#else
    snprintf(filename, sizeof(filename), "/tmp/env_artifacts_report.html");
#endif

    FILE *f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "Error: could not create temp file\n");
        return -1;
    }

    const int is_vm = (snap->score >= snap->threshold);

    /* ---- HTML head + CSS ---- */
    fprintf(f,
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<title>ENV-Artifact Detector Report</title>\n"
        "<style>\n"
        "body{font-family:'Segoe UI',Tahoma,sans-serif;margin:40px;background:#f5f5f5;color:#333}\n"
        ".container{max-width:920px;margin:0 auto;background:#fff;padding:30px;border-radius:8px;"
        "box-shadow:0 2px 8px rgba(0,0,0,.1)}\n"
        "h1{text-align:center}\n"
        ".verdict-vm{background:#dc3545;color:#fff;padding:20px;border-radius:6px;"
        "text-align:center;font-size:1.4em;margin:20px 0}\n"
        ".verdict-bm{background:#28a745;color:#fff;padding:20px;border-radius:6px;"
        "text-align:center;font-size:1.4em;margin:20px 0}\n"
        "table{width:100%%;border-collapse:collapse;margin:15px 0}\n"
        "th,td{padding:8px 12px;border:1px solid #ddd;text-align:left}\n"
        "th{background:#f8f9fa}\n"
        ".passed{color:#28a745;font-weight:700}\n"
        ".failed{color:#dc3545;font-weight:700}\n"
        ".error{color:#ffc107;font-weight:700}\n"
        "h2{border-bottom:2px solid #007bff;padding-bottom:5px;margin-top:30px}\n"
        "h3{color:#555}\n"
        ".tip{background:#fff3cd;border-left:4px solid #ffc107;padding:10px 15px;"
        "margin:10px 0;white-space:pre-line}\n"
        ".tip-summary{font-style:italic;margin-bottom:10px;color:#555}\n"
        ".method-card{background:#f8f9fa;border:1px solid #dee2e6;border-radius:6px;"
        "padding:12px 16px;margin:8px 0}\n"
        ".method-card h4{margin:0 0 8px 0;color:#007bff}\n"
        ".method-card ol{margin:4px 0 0 0;padding-left:20px}\n"
        ".method-card li{margin:3px 0}\n"
        "footer{text-align:center;margin-top:40px;color:#999;font-size:.85em;"
        "border-top:1px solid #eee;padding-top:15px}\n"
        ".meta{color:#666;font-size:.9em}\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<div class=\"container\">\n");

    /* ---- Title ---- */
    fprintf(f, "<h1>ENV-Artifact Detector Report</h1>\n");

    /* ---- Metadata ---- */
    fprintf(f, "<p class=\"meta\">"
               "Timestamp: %s &bull; Build: %s &bull; OS: ",
            snap->meta.timestamp, snap->meta.build_config);
    fprint_escaped(f, snap->meta.os_version);
    fprintf(f, " &bull; Arch: %s", snap->meta.architecture);
    if (snap->meta.run_tag[0]) {
        fprintf(f, " &bull; Tag: ");
        fprint_escaped(f, snap->meta.run_tag);
    }
    fprintf(f, "</p>\n");

    /* ---- Verdict banner ---- */
    fprintf(f,
        "<div class=\"%s\">\n"
        "%s<br>\n"
        "Suspicion score: %d / %d (threshold)\n"
        "</div>\n",
        is_vm ? "verdict-vm" : "verdict-bm",
        is_vm ? "LIKELY VIRTUALISED" : "LIKELY BARE METAL",
        snap->score, snap->threshold);

    /* ---- Check results table ---- */
    fprintf(f, "<h2>Check Results</h2>\n");
    fprintf(f,
        "<table>\n"
        "<tr><th>Label</th><th>Status</th><th>Weight</th><th>Reason</th></tr>\n");
    for (int i = 0; i < snap->num_checks; i++) {
        const check_result *r = &snap->results[i];
        const char *cls = (r->status == CHECK_PASSED) ? "passed" :
                          (r->status == CHECK_FAILED) ? "failed" : "error";
        fprintf(f, "<tr><td>");
        fprint_escaped(f, r->label ? r->label : "");
        fprintf(f, "</td><td class=\"%s\">%s</td><td>%d</td><td>",
                cls, status_str(r->status), r->weight);
        if (r->reason && r->reason[0])
            fprint_escaped(f, r->reason);
        else
            fprintf(f, "-");
        fprintf(f, "</td></tr>\n");
    }
    fprintf(f, "</table>\n");

    /* ---- Detailed data sections ---- */
    fprintf(f, "<h2>Detailed Data</h2>\n");

    /* BIOS */
    fprintf(f, "<h3>BIOS</h3>\n<table>\n");
    fprintf(f, "<tr><td><b>Vendor</b></td><td>");
    fprint_escaped(f, snap->bios.vendor[0]  ? snap->bios.vendor  : "(empty)");
    fprintf(f, "</td></tr>\n<tr><td><b>Version</b></td><td>");
    fprint_escaped(f, snap->bios.version[0] ? snap->bios.version : "(empty)");
    fprintf(f, "</td></tr>\n<tr><td><b>Product</b></td><td>");
    fprint_escaped(f, snap->bios.product[0] ? snap->bios.product : "(empty)");
    fprintf(f, "</td></tr>\n</table>\n");

    /* MAC */
    fprintf(f, "<h3>MAC Address</h3>\n<table>\n");
    fprintf(f, "<tr><td><b>Address</b></td><td>%s</td></tr>\n",
            snap->mac.address[0] ? snap->mac.address : "(empty)");
    fprintf(f, "<tr><td><b>Vendor</b></td><td>");
    fprint_escaped(f, snap->mac.vendor[0] ? snap->mac.vendor : "(empty)");
    fprintf(f, "</td></tr>\n</table>\n");

    /* Drivers */
    fprintf(f, "<h3>Virtual Drivers (%d detected)</h3>\n", snap->driver_count);
    if (snap->driver_count > 0) {
        fprintf(f, "<table>\n<tr><th>#</th><th>Name</th><th>Vendor</th><th>Loaded</th></tr>\n");
        for (int i = 0; i < snap->driver_count; i++) {
            fprintf(f, "<tr><td>%d</td><td>", i + 1);
            fprint_escaped(f, snap->drivers[i].name);
            fprintf(f, "</td><td>");
            fprint_escaped(f, snap->drivers[i].vendor[0] ? snap->drivers[i].vendor : "-");
            fprintf(f, "</td><td>%s</td></tr>\n",
                    snap->drivers[i].loaded ? "yes" : "no");
        }
        fprintf(f, "</table>\n");
    } else {
        fprintf(f, "<p>(none)</p>\n");
    }

    /* Registry */
    fprintf(f, "<h3>Registry Artefacts (%d detected)</h3>\n", snap->reg_count);
    if (snap->reg_count > 0) {
        fprintf(f, "<table>\n<tr><th>#</th><th>Path</th><th>Description</th></tr>\n");
        for (int i = 0; i < snap->reg_count; i++) {
            fprintf(f, "<tr><td>%d</td><td>", i + 1);
            fprint_escaped(f, snap->reg_hits[i].path);
            fprintf(f, "</td><td>");
            fprint_escaped(f, snap->reg_hits[i].description);
            fprintf(f, "</td></tr>\n");
        }
        fprintf(f, "</table>\n");
    } else {
        fprintf(f, "<p>(none)</p>\n");
    }

    /* Filesystem */
    fprintf(f, "<h3>Filesystem Artefacts (%d detected)</h3>\n", snap->fs_count);
    if (snap->fs_count > 0) {
        fprintf(f, "<table>\n<tr><th>#</th><th>Path</th><th>Description</th></tr>\n");
        for (int i = 0; i < snap->fs_count; i++) {
            fprintf(f, "<tr><td>%d</td><td>", i + 1);
            fprint_escaped(f, snap->fs_hits[i].path);
            fprintf(f, "</td><td>");
            fprint_escaped(f, snap->fs_hits[i].description);
            fprintf(f, "</td></tr>\n");
        }
        fprintf(f, "</table>\n");
    } else {
        fprintf(f, "<p>(none)</p>\n");
    }

    /* Timing */
    fprintf(f, "<h3>Timing</h3>\n<table>\n");
    fprintf(f, "<tr><td><b>Sleep actual</b></td><td>%" PRIu64 " ms</td></tr>\n",
            snap->timing.sleep_ms_actual);
    fprintf(f, "<tr><td><b>RDTSC delta</b></td><td>%" PRIu64 "</td></tr>\n",
            snap->timing.rdtsc_delta);
    fprintf(f, "<tr><td><b>Loop median</b></td><td>%.3f ms</td></tr>\n",
            snap->timing.loop.median_ms);
    fprintf(f, "<tr><td><b>Loop P95</b></td><td>%.3f ms</td></tr>\n",
            snap->timing.loop.p95_ms);
    fprintf(f, "<tr><td><b>Loop min / max</b></td><td>%.3f / %.3f ms</td></tr>\n",
            snap->timing.loop.min_ms, snap->timing.loop.max_ms);
    fprintf(f, "<tr><td><b>Loop samples</b></td><td>%d</td></tr>\n",
            snap->timing.loop.samples);
    fprintf(f, "</table>\n");

    /* CPUID */
    fprintf(f, "<h3>CPUID</h3>\n<table>\n");
    fprintf(f, "<tr><td><b>Architecture</b></td><td>%s</td></tr>\n", snap->cpuid.arch);
    fprintf(f, "<tr><td><b>Supported</b></td><td>%s</td></tr>\n",
            snap->cpuid.supported ? "yes" : "no");
    fprintf(f, "<tr><td><b>Leaf 1 ECX</b></td><td>0x%08X</td></tr>\n",
            (unsigned)snap->cpuid.leaf_1_ecx);
    fprintf(f, "<tr><td><b>Hypervisor bit</b></td><td>%s</td></tr>\n",
            snap->cpuid.hypervisor_bit ? "SET" : "clear");
    fprintf(f, "</table>\n");

    /* VMware backdoor */
    fprintf(f, "<h3>VMware Backdoor</h3>\n<table>\n");
    fprintf(f, "<tr><td><b>Supported</b></td><td>%s</td></tr>\n",
            snap->vmware.supported ? "yes" : "no");
    fprintf(f, "<tr><td><b>Detected</b></td><td>%s</td></tr>\n",
            snap->vmware.detected  ? "yes" : "no");
    fprintf(f, "</table>\n");

#ifdef _WIN32
    /* Debugger */
    fprintf(f, "<h3>Debugger</h3>\n<table>\n");
    fprintf(f, "<tr><td><b>IsDebuggerPresent</b></td><td>%s</td></tr>\n",
            snap->debugger.is_debugger_present     ? "yes" : "no");
    fprintf(f, "<tr><td><b>RemoteDebuggerPresent</b></td><td>%s</td></tr>\n",
            snap->debugger.remote_debugger_present  ? "yes" : "no");
    fprintf(f, "<tr><td><b>PEB-&gt;BeingDebugged</b></td><td>%s</td></tr>\n",
            snap->debugger.peb_being_debugged       ? "yes" : "no");
    fprintf(f, "<tr><td><b>ProcessDebugPort</b></td><td>%s (detected: %s)</td></tr>\n",
            snap->debugger.process_debug_port.supported  ? "supported" : "N/A",
            snap->debugger.process_debug_port.detected   ? "yes" : "no");
    fprintf(f, "<tr><td><b>ProcessDebugFlags</b></td><td>%s (detected: %s)</td></tr>\n",
            snap->debugger.process_debug_flags.supported ? "supported" : "N/A",
            snap->debugger.process_debug_flags.detected  ? "yes" : "no");
    fprintf(f, "<tr><td><b>ProcessDebugObject</b></td><td>%s (detected: %s)</td></tr>\n",
            snap->debugger.process_debug_object.supported ? "supported" : "N/A",
            snap->debugger.process_debug_object.detected  ? "yes" : "no");
    fprintf(f, "</table>\n");
#endif

    /* ---- Recommendations section (multi-method layout) ---- */
    fprintf(f, "<h2>Recommendations</h2>\n");
    {
        int any = 0;
        for (int i = 0; i < snap->num_checks; i++) {
            if (snap->results[i].status != CHECK_FAILED) continue;
            const check_tip *tip = tip_for_check(snap->results[i].label);
            if (!tip) continue;
            any = 1;

            fprintf(f, "<div class=\"tip\"><b>");
            fprint_escaped(f, snap->results[i].label);
            fprintf(f, "</b>\n");
            fprintf(f, "<p class=\"tip-summary\">");
            fprint_escaped(f, tip->summary);
            fprintf(f, "</p>\n");

            for (int m = 0; m < tip->num_methods; m++) {
                if (!tip->methods[m].title) break;
                fprintf(f, "<div class=\"method-card\"><h4>");
                fprint_escaped(f, tip->methods[m].title);
                fprintf(f, "</h4>\n<ol>\n");

                /* Parse numbered steps into <li> items */
                const char *p = tip->methods[m].steps;
                while (p && *p) {
                    /* Skip leading whitespace and step number prefix like "1. " */
                    while (*p == ' ' || *p == '\t') p++;
                    if (*p >= '0' && *p <= '9') {
                        while (*p >= '0' && *p <= '9') p++;
                        if (*p == '.') p++;
                        if (*p == ' ') p++;
                    }
                    if (*p == '\0') break;

                    fprintf(f, "<li>");
                    /* Collect text until newline */
                    while (*p && *p != '\n') {
                        /* Escape HTML chars inline */
                        switch (*p) {
                            case '&': fputs("&amp;", f); break;
                            case '<': fputs("&lt;", f); break;
                            case '>': fputs("&gt;", f); break;
                            case '"': fputs("&quot;", f); break;
                            default:  fputc(*p, f); break;
                        }
                        p++;
                    }
                    /* If next line starts with whitespace (continuation), append it */
                    while (*p == '\n' && *(p + 1) == ' ' && !(*(p + 1) == ' ' && *(p + 2) >= '0' && *(p + 2) <= '9')) {
                        /* Check it's truly a continuation, not a new numbered step */
                        const char *ahead = p + 1;
                        while (*ahead == ' ' || *ahead == '\t') ahead++;
                        if (*ahead >= '0' && *ahead <= '9') break; /* new step */
                        fputc(' ', f);
                        p++; /* skip \n */
                        while (*p == ' ' || *p == '\t') p++;
                        while (*p && *p != '\n') {
                            switch (*p) {
                                case '&': fputs("&amp;", f); break;
                                case '<': fputs("&lt;", f); break;
                                case '>': fputs("&gt;", f); break;
                                case '"': fputs("&quot;", f); break;
                                default:  fputc(*p, f); break;
                            }
                            p++;
                        }
                    }
                    fprintf(f, "</li>\n");
                    if (*p == '\n') p++;
                }
                fprintf(f, "</ol>\n</div>\n");
            }
            fprintf(f, "</div>\n");
        }
        if (!any) {
            fprintf(f, "<p>All checks passed &mdash; no remediation needed.</p>\n");
        }
    }

    /* ---- Footer ---- */
    {
        char ts[32];
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
        fprintf(f,
            "<footer>ENV-Artifact Detector v1.1.0 &bull; Report generated %s</footer>\n",
            ts);
    }

    fprintf(f, "</div>\n</body>\n</html>\n");
    fclose(f);

    printf("  Opening report in browser...\n");

#ifdef _WIN32
    ShellExecuteA(NULL, "open", filename, NULL, NULL, SW_SHOWNORMAL);
#else
    {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "xdg-open \"%s\" 2>/dev/null &", filename);
        system(cmd);
    }
#endif

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Elevation helpers                                                  */
/* ------------------------------------------------------------------ */

#ifdef _WIN32
static bool is_elevated(void) {
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
}

/* Relaunch the detector as Administrator with the given CLI flags.
   The elevated process runs independently; returns true if launched. */
static bool relaunch_elevated(const char *args) {
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);

    /* Get current working directory so the elevated process uses the same
       CWD.  Without this, ShellExecuteEx defaults to C:\Windows\System32
       and all relative paths (logs/, backup files) break. */
    char cwd[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, cwd);

    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "runas";
    sei.lpFile = exe_path;
    sei.lpParameters = args;
    sei.lpDirectory = cwd;
    sei.nShow = SW_SHOWNORMAL;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    if (ShellExecuteExA(&sei)) {
        printf("  Elevated process launched. Waiting for it to finish...\n");
        WaitForSingleObject(sei.hProcess, INFINITE);
        CloseHandle(sei.hProcess);
        return true;
    }
    printf("  Elevation was cancelled or failed.\n");
    return false;
}
#endif

/* ------------------------------------------------------------------ */
/*  show_auto_remediate — apply guest-side fixes interactively         */
/* ------------------------------------------------------------------ */

void show_auto_remediate(scan_snapshot *snap) {
    char line[16];
    int choice;

    printf("\n");
    printf("  ==============================================\n");
    printf("  AUTO-REMEDIATE (GUEST-SIDE FIXES)\n");
    printf("  ==============================================\n");
    printf("  Select which section(s) to harden:\n\n");
    printf("  1  Hardware / Firmware  (BIOS spoof + MAC spoof)\n");
    printf("  2  VM Artefacts        (registry, filesystem, services, drivers)\n");
    printf("  3  Timing              (host-side only -- generates config patch)\n");
    printf("  4  Hypervisor          (host-side only -- generates config patch)\n");
    printf("  5  Debugger            (host-side only -- generates config patch)\n");
    printf("  6  All (full evasion hardening)\n");
    printf("  0  Cancel\n");
    printf("  ==============================================\n");
    printf("  Choice: ");
    fflush(stdout);

    if (!fgets(line, sizeof(line), stdin)) return;
    if (sscanf(line, "%d", &choice) != 1 || choice < 0 || choice > 6) {
        printf("  Invalid choice.\n");
        return;
    }
    if (choice == 0) return;

    /* Determine fix mask based on section choice */
    int fix_mask = 0;
    bool need_patch = false;

    switch (choice) {
        case 1:  /* Hardware / Firmware: BIOS spoof + MAC spoof */
            fix_mask = FIX_BIOS | FIX_MAC_SPOOF;
            break;
        case 2:  /* VM Artefacts */
            fix_mask = FIX_REGISTRY | FIX_FILESYSTEM | FIX_SERVICES | FIX_DRIVERS;
            break;
        case 3:  /* Timing — host-side only */
        case 4:  /* Hypervisor — host-side only */
        case 5:  /* Debugger — host-side only */
            need_patch = true;
            break;
        case 6:  /* All */
            fix_mask = FIX_ALL_GUEST;
            need_patch = true;
            break;
    }

    /* Guest-side fixes require elevation */
    if (fix_mask != 0) {
        printf("\n  A rollback file will be created so you can undo changes.\n");

#ifdef _WIN32
        if (!is_elevated()) {
            printf("\n  This operation requires Administrator privileges.\n");
            printf("  Relaunch with elevation? [y/N]: ");
            fflush(stdout);
            if (!fgets(line, sizeof(line), stdin)) return;
            if (line[0] == 'y' || line[0] == 'Y') {
                /* Build CLI args with the exact fix mask the user chose */
                char args[256];
                snprintf(args, sizeof(args),
                         "--auto-fix --fix-mask %d --compare --no-interactive --verbose",
                         fix_mask);
                relaunch_elevated(args);
            } else {
                printf("  Guest-side fixes skipped.\n");
            }
        } else {
            rollback_manifest manifest;
            remediation_report report;
            int rc = remediate_apply(snap, fix_mask, &manifest, &report, true);
            if (rc == 0)
                remediate_print_report(&report);
        }
#else
        rollback_manifest manifest;
        remediation_report report;
        int rc = remediate_apply(snap, fix_mask, &manifest, &report, true);
        if (rc == 0)
            remediate_print_report(&report);
#endif
    }

    /* Offer host-side patch when relevant (BIOS, timing, etc.) */
    if (need_patch) {
        const char *msg = (fix_mask != 0)
            ? "\n  Some checks (e.g. BIOS) can only be fixed from the host side.\n"
              "  Generate a host-side config patch? [y/N]: "
            : "\n  This section can only be fixed from the host side.\n"
              "  Generate a host-side config patch? [y/N]: ";
        printf("%s", msg);
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) return;
        if (line[0] == 'y' || line[0] == 'Y') {
            show_host_patches(snap);
        }
    }
}

/* ------------------------------------------------------------------ */
/*  show_profile_select — choose and apply a hardening profile         */
/* ------------------------------------------------------------------ */

void show_profile_select(scan_snapshot *snap) {
    int pid = profile_select_interactive();
    if (pid < 0) return;

    /* Ask for platform */
    printf("\n  Which hypervisor?\n");
    printf("  1  VMware\n");
    printf("  2  VirtualBox\n");
    printf("  3  KVM / QEMU\n");
    printf("  4  Hyper-V\n");
    printf("  Choice: ");
    fflush(stdout);

    char line[16];
    if (!fgets(line, sizeof(line), stdin)) return;
    int plat_choice;
    if (sscanf(line, "%d", &plat_choice) != 1 || plat_choice < 1 || plat_choice > 4)
        return;

    hypervisor_platform plat = (hypervisor_platform)(plat_choice - 1);

#ifdef _WIN32
    if (!is_elevated()) {
        printf("\n  This operation requires Administrator privileges.\n");
        printf("  Relaunch with elevation? [y/N]: ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) return;
        if (line[0] != 'y' && line[0] != 'Y') {
            printf("  Aborted.\n");
            return;
        }
        const char *prof_names[] = {"light", "moderate", "aggressive"};
        const char *plat_names_cli[] = {"vmware", "vbox", "kvm", "hyperv"};
        char args[256];
        snprintf(args, sizeof(args),
                 "--profile %s --platform %s --compare --no-interactive --verbose",
                 prof_names[pid], plat_names_cli[plat]);
        relaunch_elevated(args);
        return;
    }
#endif

    profile_apply(snap, (profile_id)pid, plat, true);
}

/* ------------------------------------------------------------------ */
/*  show_host_patches — generate host-side config patches              */
/* ------------------------------------------------------------------ */

void show_host_patches(const scan_snapshot *snap) {
    printf("\n  Which hypervisor?\n");
    printf("  1  VMware\n");
    printf("  2  VirtualBox\n");
    printf("  3  KVM / QEMU\n");
    printf("  4  Hyper-V\n");
    printf("  0  Cancel\n");
    printf("  Choice: ");
    fflush(stdout);

    char line[16];
    if (!fgets(line, sizeof(line), stdin)) return;
    int choice;
    if (sscanf(line, "%d", &choice) != 1 || choice < 0 || choice > 4) return;
    if (choice == 0) return;

    hypervisor_platform plat = (hypervisor_platform)(choice - 1);

    /* Preview to screen */
    patchgen_preview(snap, plat);

    /* Ask to save */
    printf("\n  Save to file? [y/N]: ");
    fflush(stdout);
    if (!fgets(line, sizeof(line), stdin)) return;
    if (line[0] == 'y' || line[0] == 'Y') {
        char path[256];
        patchgen_generate(snap, plat, path, sizeof(path));
        printf("  Saved to: %s\n", path);
    }
}

/* ------------------------------------------------------------------ */
/*  show_comparison — display before/after comparison                  */
/* ------------------------------------------------------------------ */

void show_comparison(const scan_snapshot *baseline, const scan_snapshot *snap) {
    if (!baseline) {
        printf("\n  No baseline available. Run a scan, apply fixes, then re-scan.\n");
        return;
    }

    compare_result result;
    compare_snapshots(baseline, snap, &result);
    compare_print(&result);
}

/* ------------------------------------------------------------------ */
/*  show_rollback_menu — list and execute rollback files                */
/* ------------------------------------------------------------------ */

void show_rollback_menu(void) {
    printf("\n");
    printf("  ==============================================\n");
    printf("  ROLLBACK PREVIOUS CHANGES\n");
    printf("  ==============================================\n");

    /* List rollback files in logs/ directory */
#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("logs/rollback_*.json", &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("  No rollback files found in logs/\n");
        printf("  ==============================================\n");
        return;
    }

    char files[32][256];
    int file_count = 0;

    do {
        if (file_count < 32) {
            snprintf(files[file_count], sizeof(files[0]), "logs/%s", fd.cFileName);
            file_count++;
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
#else
    /* On non-Windows, just prompt for a filename */
    char files[1][256];
    int file_count = 0;
    printf("  Enter rollback file path: ");
    fflush(stdout);
    char input[256];
    if (fgets(input, sizeof(input), stdin)) {
        input[strcspn(input, "\n")] = '\0';
        if (input[0]) {
            snprintf(files[0], sizeof(files[0]), "%s", input);
            file_count = 1;
        }
    }
#endif

    if (file_count == 0) {
        printf("  No rollback files found.\n");
        printf("  ==============================================\n");
        return;
    }

    for (int i = 0; i < file_count; i++)
        printf("  %d  %s\n", i + 1, files[i]);
    printf("  0  Cancel\n");
    printf("  ==============================================\n");
    printf("  Choice: ");
    fflush(stdout);

    char line[16];
    if (!fgets(line, sizeof(line), stdin)) return;
    int choice;
    if (sscanf(line, "%d", &choice) != 1 || choice < 0 || choice > file_count) return;
    if (choice == 0) return;

    rollback_manifest manifest;
    if (rollback_load(&manifest, files[choice - 1]) != 0) {
        printf("  Failed to load rollback file.\n");
        return;
    }

    printf("  Loaded %d entries (profile: %s, time: %s)\n",
           manifest.count, manifest.profile, manifest.timestamp);
    printf("  Execute rollback? [y/N]: ");
    fflush(stdout);
    if (!fgets(line, sizeof(line), stdin)) return;
    if (line[0] != 'y' && line[0] != 'Y') {
        printf("  Aborted.\n");
        return;
    }

#ifdef _WIN32
    if (!is_elevated()) {
        printf("\n  This operation requires Administrator privileges.\n");
        printf("  Relaunch with elevation? [y/N]: ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) return;
        if (line[0] != 'y' && line[0] != 'Y') {
            printf("  Aborted.\n");
            return;
        }
        char args[512];
        snprintf(args, sizeof(args), "--rollback %s", files[choice - 1]);
        relaunch_elevated(args);
        return;
    }
#endif

    int restored = rollback_execute(&manifest, true);
    printf("  Rollback complete: %d/%d entries restored.\n",
           restored, manifest.count);
}

/* ------------------------------------------------------------------ */
/*  interactive_menu                                                   */
/* ------------------------------------------------------------------ */

int interactive_menu(scan_snapshot *snap, const scan_snapshot *baseline) {
    char line[64];
    int choice;

    for (;;) {
        printf("\n");
        printf("==============================================\n");
        printf("  POST-SCAN MENU\n");
        printf("==============================================\n");
        printf("  1  View detailed data\n");
        printf("  2  View recommendations\n");
        printf("  3  Export HTML report\n");
        printf("  4  Re-run scan\n");
        printf("  5  Step-by-step fix guide\n");
        printf("  6  Evasion playbook\n");
        printf("  7  Auto-remediate (apply guest-side fixes)\n");
        printf("  8  Apply hardening profile\n");
        printf("  9  Generate host-side config patches\n");
        printf(" 10  View before/after comparison\n");
        printf(" 11  Rollback previous changes\n");
        printf("  0  Exit\n");
        printf("==============================================\n");
        printf("  Choice: ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin))
            return 0;  /* EOF -> exit */

        if (sscanf(line, "%d", &choice) != 1)
            continue;  /* invalid input -> re-prompt */

        switch (choice) {
            case 1:  show_detailed_data(snap);              break;
            case 2:  show_recommendations(snap);            break;
            case 3:  export_html_report(snap);              break;
            case 4:  return 1;  /* rerun */
            case 5:  show_fix_guide(snap);                  break;
            case 6:  show_evasion_playbook(snap);           break;
            case 7:  show_auto_remediate(snap);             break;
            case 8:  show_profile_select(snap);             break;
            case 9:  show_host_patches(snap);               break;
            case 10: show_comparison(baseline, snap);       break;
            case 11: show_rollback_menu();                  break;
            case 0:  return 0;  /* exit  */
            default:
                printf("  Invalid choice.\n");
                break;
        }
    }
}
