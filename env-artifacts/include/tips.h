#pragma once

/* A single fix method with a title and numbered step-by-step instructions. */
typedef struct {
    const char *title;   /* e.g. "Method 1: Edit VMware config file (.vmx)" */
    const char *steps;   /* numbered steps, e.g. "1. Open .vmx\n2. Add line..." */
} tip_method;

/* Hypervisor platforms for the evasion playbook. */
typedef enum {
    PLATFORM_VMWARE = 0,
    PLATFORM_VBOX,
    PLATFORM_KVM,
    PLATFORM_HYPERV,
    PLATFORM_COUNT
} hypervisor_platform;

/* Per-platform fix: host-side config/commands + guest-side actions. */
typedef struct {
    const char *config_lines;  /* config file lines or host commands (NULL if N/A) */
    const char *guest_steps;   /* actions inside the running VM   (NULL if N/A) */
} platform_fix;

/* Full tip for one check: plain-English summary + multiple fix methods +
   per-platform quick-fix data for the evasion playbook. */
typedef struct {
    const char *label;       /* check label (matches check_result.label) */
    const char *summary;     /* 1-sentence plain-English explanation */
    int         num_methods; /* 1-4 */
    tip_method  methods[4];
    platform_fix platforms[PLATFORM_COUNT]; /* indexed by hypervisor_platform */
} check_tip;

/* Return the full tip struct for a check label, or NULL if unknown. */
const check_tip *tip_for_check(const char *label);
