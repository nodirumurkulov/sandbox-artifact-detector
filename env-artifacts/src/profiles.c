#include "profiles.h"
#include "patchgen.h"
#include "rollback.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Static profile definitions                                         */
/* ------------------------------------------------------------------ */

static const profile_descriptor g_profiles[PROFILE_COUNT] = {
    {
        PROFILE_LIGHT,
        "Light",
        "Registry + Filesystem + MAC (guest-side only, no host patch)",
        FIX_REGISTRY | FIX_FILESYSTEM | FIX_MAC_SPOOF,
        false,  /* no patch */
        false   /* no timing tips */
    },
    {
        PROFILE_MODERATE,
        "Moderate",
        "Light fixes + host-side config patch generation",
        FIX_REGISTRY | FIX_FILESYSTEM | FIX_MAC_SPOOF,
        true,   /* generate patch */
        false
    },
    {
        PROFILE_AGGRESSIVE,
        "Aggressive",
        "All guest-side fixes + host patch + timing recommendations",
        FIX_ALL_GUEST,
        true,   /* generate patch */
        true    /* timing tips */
    }
};

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

const profile_descriptor *profile_get(profile_id id) {
    if (id < 0 || id >= PROFILE_COUNT) return NULL;
    return &g_profiles[id];
}

int profile_select_interactive(void) {
    printf("\n");
    printf("  ==============================================\n");
    printf("  SELECT HARDENING PROFILE\n");
    printf("  ==============================================\n");
    for (int i = 0; i < PROFILE_COUNT; i++) {
        printf("  %d  %-12s  %s\n",
               i + 1, g_profiles[i].name, g_profiles[i].description);
    }
    printf("  0  Cancel\n");
    printf("  ==============================================\n");
    printf("  Choice: ");
    fflush(stdout);

    char line[16];
    if (!fgets(line, sizeof(line), stdin))
        return -1;

    int choice;
    if (sscanf(line, "%d", &choice) != 1 || choice < 0 || choice > PROFILE_COUNT)
        return -1;
    if (choice == 0) return -1;

    return choice - 1;  /* convert to profile_id */
}

int profile_apply(scan_snapshot *snap,
                  profile_id profile,
                  hypervisor_platform platform,
                  bool confirm) {
    const profile_descriptor *pd = profile_get(profile);
    if (!pd) {
        fprintf(stderr, "  Invalid profile.\n");
        return -1;
    }

    printf("  Applying profile: %s\n", pd->name);
    printf("  %s\n\n", pd->description);

    /* Run guest-side remediation */
    rollback_manifest manifest;
    remediation_report report;

    int rc = remediate_apply(snap, pd->fix_mask, &manifest, &report, confirm);
    if (rc != 0) return rc;

    remediate_print_report(&report);

    /* Optionally generate host-side config patch */
    if (pd->generate_patch) {
        printf("\n  Generating host-side config patch...\n");
        char patch_path[256];
        patchgen_generate(snap, platform, patch_path, sizeof(patch_path));
        printf("  Patch file saved to: %s\n", patch_path);
    }

    /* Optionally print timing tips */
    if (pd->timing_tips) {
        printf("\n  ==============================================\n");
        printf("  TIMING RECOMMENDATIONS\n");
        printf("  ==============================================\n");
        printf("  - Use a dedicated CPU core for the VM to reduce jitter\n");
        printf("  - Avoid running other VMs concurrently during detection\n");
        printf("  - Disable nested virtualisation if not needed\n");
        printf("  - On VMware: add 'monitor_control.disable_apichv = \"TRUE\"'\n");
        printf("  - On KVM: use '-cpu host' for closest timing match\n");
        printf("  - On VirtualBox: enable 'Use Host I/O Cache'\n");
        printf("  ==============================================\n");
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Config save / load (JSON)                                          */
/* ------------------------------------------------------------------ */

int profile_save_config(profile_id profile, hypervisor_platform platform,
                        const char *filepath) {
    FILE *f = fopen(filepath, "w");
    if (!f) return -1;

    const profile_descriptor *pd = profile_get(profile);
    const char *plat_names[] = {"vmware", "vbox", "kvm", "hyperv"};

    fprintf(f, "{\n");
    fprintf(f, "  \"profile\": \"%s\",\n", pd ? pd->name : "unknown");
    fprintf(f, "  \"profile_id\": %d,\n", (int)profile);
    fprintf(f, "  \"platform\": \"%s\",\n",
            (platform >= 0 && platform < PLATFORM_COUNT)
                ? plat_names[platform] : "unknown");
    fprintf(f, "  \"platform_id\": %d\n", (int)platform);
    fprintf(f, "}\n");

    fclose(f);
    return 0;
}

int profile_load_config(profile_id *profile, hypervisor_platform *platform,
                        const char *filepath) {
    FILE *f = fopen(filepath, "r");
    if (!f) return -1;

    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);

    /* Parse profile_id */
    const char *p = strstr(buf, "\"profile_id\"");
    if (p) {
        p = strchr(p, ':');
        if (p) *profile = (profile_id)atoi(p + 1);
    }

    /* Parse platform_id */
    p = strstr(buf, "\"platform_id\"");
    if (p) {
        p = strchr(p, ':');
        if (p) *platform = (hypervisor_platform)atoi(p + 1);
    }

    return 0;
}
