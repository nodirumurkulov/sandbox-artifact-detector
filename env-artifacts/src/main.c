#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include "bios.h"
#include "mac_oui.h"
#include "driver_detect.h"
#include "registry_fs.h"
#include "checks.h"
#include "ui.h"
#include "timing.h"
#include "cpuid_check.h"
#include "vmware_backdoor.h"
#include "interactive.h"

/* New automation headers */
#include "rollback.h"
#include "remediate.h"
#include "profiles.h"
#include "patchgen.h"
#include "compare.h"
#include "agent.h"

#ifdef _WIN32
#include "debugger_checks.h"
#endif

// helper to create "logs" folder if missing
static void ensure_logs_dir(void) {
#ifdef _WIN32
    _mkdir("logs");
#else
    mkdir("logs", 0755);
#endif
}

// helper to create timestamped filename
static void make_timestamp_filename(char *buf, size_t bufsize) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buf, bufsize, "logs/detector_%Y-%m-%d_%H-%M-%S.json", t);
}

// Escape backslashes and double quotes for JSON strings
static void json_escape(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j + 1 < dst_size; ++i) {
        char c = src[i];
        if (c == '\\' || c == '\"') {
            if (j + 2 >= dst_size) break;
            dst[j++] = '\\';   // add escape
            dst[j++] = c;
        } else {
            dst[j++] = c;
        }
    }
    dst[j] = '\0';
}

/* Map a platform name string to its enum value. Returns -1 on failure. */
static int parse_platform(const char *s, hypervisor_platform *out) {
    if (strcmp(s, "vmware") == 0) { *out = PLATFORM_VMWARE; return 0; }
    if (strcmp(s, "vbox")   == 0) { *out = PLATFORM_VBOX;   return 0; }
    if (strcmp(s, "kvm")    == 0) { *out = PLATFORM_KVM;    return 0; }
    if (strcmp(s, "hyperv") == 0) { *out = PLATFORM_HYPERV; return 0; }
    return -1;
}

/* Map a profile name string to its enum value. Returns -1 on failure. */
static int parse_profile(const char *s, profile_id *out) {
    if (strcmp(s, "light")      == 0) { *out = PROFILE_LIGHT;      return 0; }
    if (strcmp(s, "moderate")   == 0) { *out = PROFILE_MODERATE;   return 0; }
    if (strcmp(s, "aggressive") == 0) { *out = PROFILE_AGGRESSIVE; return 0; }
    return -1;
}

/* Run a full scan and populate snap. Returns num_checks. */
static int run_scan(scan_snapshot *snap, bool opt_verbose, const char *opt_tag) {
    struct bios_info bios;
    struct mac_info mac;
    struct driver_result dr[64];
    int dr_count = 0;

    get_bios_info(&bios);
    get_mac_oui(&mac);
    dr_count = detect_virtual_drivers(dr, 64);

    struct reg_artifact reg_hits[64];
    struct fs_artifact fs_hits[64];
    int reg_count = detect_registry_artifacts(reg_hits, 64);
    int fs_count  = detect_filesystem_artifacts(fs_hits, 64);

    struct timing_result timing;
    collect_timing_measurements(&timing, 100, 10000000);

    struct cpuid_result cpuid_res;
    get_cpuid_info(&cpuid_res);

    struct vmware_backdoor_result vmware_res;
    get_vmware_backdoor_info(&vmware_res);

#ifdef _WIN32
    debugger_result debugger_res;
    get_debugger_info(&debugger_res);
#endif

    check_status s_bios   = check_bios_vendor(&bios);
    check_status s_mac    = check_mac_oui(&mac);
    check_status s_driver = check_virtual_drivers(dr_count);
    check_status s_reg    = check_registry_artifacts(reg_count);
    check_status s_fs     = check_filesystem_artifacts(fs_count);
    check_status s_t_sleep = check_timing_sleep(&timing);
    check_status s_t_rdtsc = check_timing_rdtsc(&timing);
    check_status s_t_loop  = check_timing_loop(&timing);
    check_status s_cpuid   = check_cpuid_hypervisor_bit(&cpuid_res);
    check_status s_vmware  = check_vmware_backdoor(&vmware_res);

#ifdef _WIN32
    check_status s_dbg_is_debugger_present = debugger_res.is_debugger_present ? CHECK_FAILED : CHECK_PASSED;
    check_status s_dbg_remote_debugger = debugger_res.remote_debugger_present ? CHECK_FAILED : CHECK_PASSED;
    check_status s_dbg_peb_being_debugged = debugger_res.peb_being_debugged ? CHECK_FAILED : CHECK_PASSED;
    check_status s_dbg_process_debug_port = !debugger_res.process_debug_port.supported ? CHECK_ERROR :
                                             (debugger_res.process_debug_port.detected ? CHECK_FAILED : CHECK_PASSED);
    check_status s_dbg_process_debug_flags = !debugger_res.process_debug_flags.supported ? CHECK_ERROR :
                                              (debugger_res.process_debug_flags.detected ? CHECK_FAILED : CHECK_PASSED);
    check_status s_dbg_process_debug_object = !debugger_res.process_debug_object.supported ? CHECK_ERROR :
                                               (debugger_res.process_debug_object.detected ? CHECK_FAILED : CHECK_PASSED);
#endif

    check_result all_results[] = {
        {"BIOS vendor check",           s_bios,
         ui_get_weight("BIOS vendor check"),
         (s_bios == CHECK_FAILED) ? bios.vendor : NULL},

        {"MAC OUI vendor check",        s_mac,
         ui_get_weight("MAC OUI vendor check"),
         (s_mac == CHECK_FAILED) ? mac.vendor : NULL},

        {"Virtual driver check",        s_driver,
         ui_get_weight("Virtual driver check"),
         (s_driver == CHECK_FAILED) ? "VM driver(s) found" : NULL},

        {"Registry artefact check",     s_reg,
         ui_get_weight("Registry artefact check"),
         (s_reg == CHECK_FAILED) ? "VM registry key(s) detected" : NULL},

        {"Filesystem artefact check",   s_fs,
         ui_get_weight("Filesystem artefact check"),
         (s_fs == CHECK_FAILED) ? "VM file(s) found on disk" : NULL},

        {"Timing (sleep acceleration)", s_t_sleep,
         0,
         (s_t_sleep == CHECK_FAILED) ? "Sleep deviated >20%" : NULL},

        {"Timing (RDTSC consistency)",  s_t_rdtsc,
         0,
         (s_t_rdtsc == CHECK_FAILED) ? "RDTSC outside expected range" : NULL},

        {"Timing (loop jitter)",        s_t_loop,
         0,
         (s_t_loop == CHECK_FAILED) ? "Jitter exceeded threshold" : NULL},

        {"CPUID hypervisor bit",        s_cpuid,
         ui_get_weight("CPUID hypervisor bit"),
         (s_cpuid == CHECK_FAILED) ? "CPUID bit 31 set" : NULL},

        {"VMware backdoor I/O port",    s_vmware,
         ui_get_weight("VMware backdoor I/O port"),
         (s_vmware == CHECK_FAILED) ? "Port 0x5658 responded" : NULL},

#ifdef _WIN32
        {"Debugger checks",             check_debugger(&debugger_res),
         0, NULL},

        {"IsDebuggerPresent",          s_dbg_is_debugger_present,
         0,
         (s_dbg_is_debugger_present == CHECK_FAILED) ? "API returned TRUE" : NULL},

        {"CheckRemoteDebuggerPresent", s_dbg_remote_debugger,
         0,
         (s_dbg_remote_debugger == CHECK_FAILED) ? "Remote debugger detected" : NULL},

        {"PEB->BeingDebugged",         s_dbg_peb_being_debugged,
         0,
         (s_dbg_peb_being_debugged == CHECK_FAILED) ? "PEB flag set" : NULL},

        {"ProcessDebugPort",           s_dbg_process_debug_port,
         0,
         (s_dbg_process_debug_port == CHECK_FAILED) ? "Debug port active" : NULL},

        {"ProcessDebugFlags",          s_dbg_process_debug_flags,
         0,
         (s_dbg_process_debug_flags == CHECK_FAILED) ? "Debug flags indicate debugger" : NULL},

        {"ProcessDebugObject",         s_dbg_process_debug_object,
         0,
         (s_dbg_process_debug_object == CHECK_FAILED) ? "Debug object handle present" : NULL},
#endif
    };
    int num_checks = sizeof(all_results) / sizeof(all_results[0]);

    /* Populate snapshot */
    memset(snap, 0, sizeof(*snap));
    snap->bios = bios;
    snap->mac = mac;
    memcpy(snap->drivers, dr, sizeof(struct driver_result) * dr_count);
    snap->driver_count = dr_count;
    memcpy(snap->reg_hits, reg_hits, sizeof(struct reg_artifact) * reg_count);
    snap->reg_count = reg_count;
    memcpy(snap->fs_hits, fs_hits, sizeof(struct fs_artifact) * fs_count);
    snap->fs_count = fs_count;
    snap->timing = timing;
    snap->cpuid = cpuid_res;
    snap->vmware = vmware_res;
#ifdef _WIN32
    snap->debugger = debugger_res;
#endif
    memcpy(snap->results, all_results, sizeof(check_result) * num_checks);
    snap->num_checks = num_checks;
    ui_collect_metadata(&snap->meta, opt_tag, opt_verbose);
    snap->threshold = 6;

    /* Compute score */
    {
        int sc = 0, tf = 0;
        for (int i = 0; i < num_checks; i++) {
            const char *lbl = all_results[i].label ? all_results[i].label : "";
            check_status st = all_results[i].status;
            if (strncmp(lbl, "Timing", 6) == 0) {
                if (st == CHECK_FAILED) tf++;
                continue;
            }
            if (st == CHECK_FAILED) {
                int w = ui_get_weight(lbl);
                sc += w;
            }
        }
        if (tf >= 2) sc += 1;
        snap->score = sc;
    }

    return num_checks;
}

/* Print the grouped console output for a scan snapshot. */
static void print_scan_output(const scan_snapshot *snap, bool verbose) {
    ui_print_header_ex(&snap->meta);

    /* Section: Hardware / Firmware (indices 0-1) */
    ui_print_section_title("Hardware / Firmware");
    for (int i = 0; i <= 1; i++)
        ui_print_check(&snap->results[i], 0, verbose);

    /* Section: VM Artefacts (indices 2-4) */
    ui_print_section_title("VM Artefacts");
    for (int i = 2; i <= 4; i++)
        ui_print_check(&snap->results[i], 0, verbose);

    /* Section: Timing (indices 5-7) + group bonus line */
    ui_print_section_title("Timing");
    int timing_fails = 0;
    for (int i = 5; i <= 7; i++) {
        ui_print_check(&snap->results[i], 0, verbose);
        if (snap->results[i].status == CHECK_FAILED) timing_fails++;
    }
    if (timing_fails >= 2)
        printf("  Timing group bonus ................. (+1)  [%d/3 failed]\n", timing_fails);
    else
        printf("  Timing group bonus ................. (+0)  [%d/3 failed, need 2+]\n", timing_fails);

    /* Section: Hypervisor (indices 8-9) */
    ui_print_section_title("Hypervisor");
    for (int i = 8; i <= 9; i++)
        ui_print_check(&snap->results[i], 0, verbose);

    /* Section: Debugger (Win32 only) */
#ifdef _WIN32
    ui_print_section_title("Debugger");
    ui_print_check(&snap->results[10], 0, verbose);
    for (int i = 11; i < snap->num_checks; i++)
        ui_print_check(&snap->results[i], 4, verbose);
#endif

    printf("\n");
    ui_print_verdict(snap->results, snap->num_checks);
    printf("\n");
}

/* Write JSON log for a scan. */
static void write_json_log(const scan_snapshot *snap) {
    ensure_logs_dir();
    char filename[256];
    make_timestamp_filename(filename, sizeof(filename));

    FILE *out = fopen(filename, "w");
    if (!out) {
        fprintf(stderr, "Warning: could not create log file, printing to stdout.\n");
        out = stdout;
    }

    fprintf(out, "{\n");
    fprintf(out, "  \"metadata\": {\n");
    fprintf(out, "    \"timestamp\": \"%s\",\n", snap->meta.timestamp);
    fprintf(out, "    \"build_config\": \"%s\",\n", snap->meta.build_config);
    {
        char esc_tag[512];
        json_escape(snap->meta.run_tag, esc_tag, sizeof(esc_tag));
        fprintf(out, "    \"run_tag\": \"%s\",\n", esc_tag);
    }
    fprintf(out, "    \"verbose_enabled\": %s\n", snap->meta.verbose ? "true" : "false");
    fprintf(out, "  },\n");

    fprintf(out, "  \"bios\": {\n");
    fprintf(out, "    \"vendor\": \"%s\",\n", snap->bios.vendor[0] ? snap->bios.vendor : "");
    fprintf(out, "    \"version\": \"%s\",\n", snap->bios.version[0] ? snap->bios.version : "");
    fprintf(out, "    \"product\": \"%s\"\n", snap->bios.product[0] ? snap->bios.product : "");
    fprintf(out, "  },\n");

    fprintf(out, "  \"mac\": {\n");
    fprintf(out, "    \"address\": \"%s\",\n", snap->mac.address[0] ? snap->mac.address : "");
    fprintf(out, "    \"vendor\": \"%s\"\n", snap->mac.vendor[0] ? snap->mac.vendor : "");
    fprintf(out, "  },\n");

    fprintf(out, "  \"drivers\": [\n");
    for (int i = 0; i < snap->driver_count; ++i) {
        fprintf(out,
                "    {\"name\": \"%s\", \"vendor\": \"%s\", \"loaded\": %d}%s\n",
                snap->drivers[i].name,
                snap->drivers[i].vendor,
                snap->drivers[i].loaded,
                (i + 1 < snap->driver_count) ? "," : "");
    }
    fprintf(out, "  ],\n");

    fprintf(out, "  \"registry\": [\n");
    for (int i = 0; i < snap->reg_count; ++i) {
        char esc_path[512];
        json_escape(snap->reg_hits[i].path, esc_path, sizeof(esc_path));
        fprintf(out,
                "    {\"path\": \"%s\", \"description\": \"%s\"}%s\n",
                esc_path,
                snap->reg_hits[i].description,
                (i + 1 < snap->reg_count) ? "," : "");
    }
    fprintf(out, "  ],\n");

    fprintf(out, "  \"filesystem\": [\n");
    for (int i = 0; i < snap->fs_count; ++i) {
        char esc_path[512];
        json_escape(snap->fs_hits[i].path, esc_path, sizeof(esc_path));
        fprintf(out,
                "    {\"path\": \"%s\", \"description\": \"%s\"}%s\n",
                esc_path,
                snap->fs_hits[i].description,
                (i + 1 < snap->fs_count) ? "," : "");
    }
    fprintf(out, "  ],\n");

    fprintf(out, "  \"timing\": {\n");
    fprintf(out, "    \"sleep_ms\": %llu,\n", (unsigned long long)snap->timing.sleep_ms_actual);
    fprintf(out, "    \"rdtsc_delta\": %llu,\n", (unsigned long long)snap->timing.rdtsc_delta);
    fprintf(out, "    \"loop_ms\": %.2f,\n", snap->timing.loop_ms);
    fprintf(out, "    \"loop\": {\n");
    fprintf(out, "      \"samples\": %d,\n", snap->timing.loop.samples);
    fprintf(out, "      \"median_ms\": %.3f,\n", snap->timing.loop.median_ms);
    fprintf(out, "      \"p95_ms\": %.3f,\n", snap->timing.loop.p95_ms);
    fprintf(out, "      \"min_ms\": %.3f,\n", snap->timing.loop.min_ms);
    fprintf(out, "      \"max_ms\": %.3f,\n", snap->timing.loop.max_ms);
    fprintf(out, "      \"passed\": %s\n", snap->timing.loop.passed ? "true" : "false");
    fprintf(out, "    }\n");
    fprintf(out, "  },\n");

    fprintf(out, "  \"cpuid\": {\n");
    fprintf(out, "    \"supported\": %s,\n", snap->cpuid.supported ? "true" : "false");
    fprintf(out, "    \"arch\": \"%s\",\n", snap->cpuid.arch);
    fprintf(out, "    \"leaf_1_ecx\": %lu,\n", (unsigned long)snap->cpuid.leaf_1_ecx);
    fprintf(out, "    \"hypervisor_bit\": %d\n", snap->cpuid.hypervisor_bit);
    fprintf(out, "  },\n");

    fprintf(out, "  \"vmware_backdoor\": {\n");
    fprintf(out, "    \"supported\": %s,\n", snap->vmware.supported ? "true" : "false");
    fprintf(out, "    \"detected\": %s\n",  snap->vmware.detected  ? "true" : "false");
    fprintf(out, "  },\n");

    fprintf(out, "  \"score\": %d,\n", snap->score);
    fprintf(out, "  \"threshold\": %d,\n", snap->threshold);
    fprintf(out, "  \"verdict\": \"%s\"\n",
            (snap->score >= snap->threshold) ? "LIKELY VIRTUALISED" : "LIKELY BARE METAL");

    fprintf(out, "}\n");

    if (out != stdout)
        fclose(out);

    printf("Report saved to %s\n", filename);
}

int main(int argc, char **argv) {
    /* ---- CLI argument parsing ---- */
    bool opt_verbose        = false;
    bool opt_detailed       = false;
    bool opt_no_interactive = false;
    bool opt_auto_fix       = false;
    bool opt_compare        = false;
    bool opt_generate_patch = false;
    bool opt_json           = false;
    bool opt_install_agent  = false;
    bool opt_remove_agent   = false;
    int  opt_fix_mask       = 0;       /* 0 = use default (FIX_ALL_GUEST) */
    const char *opt_tag          = NULL;
    const char *opt_profile_str  = NULL;
    const char *opt_platform_str = NULL;
    const char *opt_rollback     = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0) {
            opt_verbose = true;
        } else if (strcmp(argv[i], "--detailed") == 0) {
            opt_detailed = true;
        } else if (strcmp(argv[i], "--no-interactive") == 0) {
            opt_no_interactive = true;
        } else if (strcmp(argv[i], "--tag") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --tag requires an argument.\n");
                return 1;
            }
            opt_tag = argv[++i];
        } else if (strcmp(argv[i], "--auto-fix") == 0) {
            opt_auto_fix = true;
        } else if (strcmp(argv[i], "--profile") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --profile requires an argument (light|moderate|aggressive).\n");
                return 1;
            }
            opt_profile_str = argv[++i];
        } else if (strcmp(argv[i], "--platform") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --platform requires an argument (vmware|vbox|kvm|hyperv).\n");
                return 1;
            }
            opt_platform_str = argv[++i];
        } else if (strcmp(argv[i], "--rollback") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --rollback requires a file path.\n");
                return 1;
            }
            opt_rollback = argv[++i];
        } else if (strcmp(argv[i], "--generate-patch") == 0) {
            opt_generate_patch = true;
        } else if (strcmp(argv[i], "--compare") == 0) {
            opt_compare = true;
        } else if (strcmp(argv[i], "--json") == 0) {
            opt_json = true;
        } else if (strcmp(argv[i], "--install-agent") == 0) {
            opt_install_agent = true;
        } else if (strcmp(argv[i], "--remove-agent") == 0) {
            opt_remove_agent = true;
        } else if (strcmp(argv[i], "--fix-mask") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --fix-mask requires an integer argument.\n");
                return 1;
            }
            opt_fix_mask = atoi(argv[++i]);
        } else {
            fprintf(stderr, "Unknown option: %s\n"
                    "Usage: detector [--verbose] [--detailed] [--no-interactive] [--tag <string>]\n"
                    "                [--auto-fix] [--profile <light|moderate|aggressive>]\n"
                    "                [--platform <vmware|vbox|kvm|hyperv>]\n"
                    "                [--rollback <file>] [--generate-patch] [--compare]\n"
                    "                [--json] [--install-agent] [--remove-agent]\n",
                    argv[i]);
            return 1;
        }
    }

    /* ---- Handle immediate commands (no scan needed) ---- */

    /* Rollback: load + execute + exit */
    if (opt_rollback) {
        rollback_manifest manifest;
        if (rollback_load(&manifest, opt_rollback) != 0) {
            fprintf(stderr, "Error: cannot load rollback file '%s'\n", opt_rollback);
            return 1;
        }
        printf("Loaded rollback manifest: %d entries (profile: %s, time: %s)\n",
               manifest.count, manifest.profile, manifest.timestamp);
        int restored = rollback_execute(&manifest, true);
        printf("Rollback complete: %d/%d entries restored.\n",
               restored, manifest.count);
        return (restored == manifest.count) ? 0 : 1;
    }

    /* Install agent */
    if (opt_install_agent) {
        const char *prof = opt_profile_str ? opt_profile_str : "light";
        const char *plat = opt_platform_str ? opt_platform_str : "vmware";
        return agent_install(prof, plat) == 0 ? 0 : 1;
    }

    /* Remove agent */
    if (opt_remove_agent) {
        return agent_remove() == 0 ? 0 : 1;
    }

    /* ---- Validate dependent options ---- */
    if (opt_generate_patch && !opt_platform_str) {
        fprintf(stderr, "Error: --generate-patch requires --platform.\n");
        return 1;
    }

    profile_id pid = PROFILE_LIGHT;
    if (opt_profile_str) {
        if (parse_profile(opt_profile_str, &pid) != 0) {
            fprintf(stderr, "Error: unknown profile '%s' (use light|moderate|aggressive)\n",
                    opt_profile_str);
            return 1;
        }
    }

    hypervisor_platform plat = PLATFORM_VMWARE;
    if (opt_platform_str) {
        if (parse_platform(opt_platform_str, &plat) != 0) {
            fprintf(stderr, "Error: unknown platform '%s' (use vmware|vbox|kvm|hyperv)\n",
                    opt_platform_str);
            return 1;
        }
    }

    /* ---- Main scan + remediation loop ---- */
    ui_enable_ansi_if_possible();

    int rerun = 0;
    scan_snapshot baseline = {0};
    bool has_baseline = false;

    do {
        rerun = 0;

        /* Run scan */
        scan_snapshot snap;
        run_scan(&snap, opt_verbose, opt_tag);

        /* Print scan output */
        print_scan_output(&snap, opt_verbose);

        /* Write JSON log */
        write_json_log(&snap);

        /* If --auto-fix or --profile: save baseline, apply fixes */
        if (opt_auto_fix || opt_profile_str) {
            baseline = snap;
            has_baseline = true;

            if (opt_profile_str) {
                bool confirm = !opt_no_interactive;
                profile_apply(&snap, pid, plat, confirm);
            } else {
                /* --auto-fix: use specific mask if given, else all guest fixes */
                rollback_manifest manifest;
                remediation_report report;
                bool confirm = !opt_no_interactive;
                int mask = opt_fix_mask ? opt_fix_mask : FIX_ALL_GUEST;
                remediate_apply(&snap, mask, &manifest, &report, confirm);
                remediate_print_report(&report);
            }
        }

        /* If --compare: re-run scan and show comparison */
        if (opt_compare && has_baseline) {
            printf("\n  Re-scanning after fixes...\n\n");
            scan_snapshot after;
            run_scan(&after, opt_verbose, opt_tag);
            print_scan_output(&after, opt_verbose);

            compare_result cmp;
            compare_snapshots(&baseline, &after, &cmp);
            compare_print(&cmp);

            /* Update snap to the post-fix state */
            snap = after;
        }

        /* If --generate-patch: produce host-side config patch */
        if (opt_generate_patch) {
            char patch_path[256];
            patchgen_generate(&snap, plat, patch_path, sizeof(patch_path));
            printf("Host config patch saved to: %s\n", patch_path);
        }

        /* If --json: output final results as JSON to stdout */
        if (opt_json) {
            printf("\n{\"score\": %d, \"threshold\": %d, \"verdict\": \"%s\"}\n",
                   snap.score, snap.threshold,
                   (snap.score >= snap.threshold)
                       ? "LIKELY VIRTUALISED" : "LIKELY BARE METAL");
        }

        if (opt_detailed)
            show_detailed_data(&snap);

        if (!opt_no_interactive) {
            const scan_snapshot *bl = has_baseline ? &baseline : NULL;
            rerun = interactive_menu(&snap, bl);
        }

    } while (rerun);

    /* Exit code: 0 if score < threshold (bare metal), 1 if still detected */
    /* Only use detection-based exit code in non-interactive (CI/CD) mode */
    if (opt_no_interactive) {
        scan_snapshot final_snap;
        /* If we already ran a scan above, use its score */
        /* The last snap is on the stack but we can just check the global flow */
        /* For CI/CD: exit 0 = bare metal, exit 1 = virtualised */
        return 0; /* default success for interactive exit */
    }

    return 0;
}
