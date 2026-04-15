#pragma once

/* Install a scheduled hardening task that runs on boot.
   - profile_name:  "light", "moderate", or "aggressive"
   - platform_name: "vmware", "vbox", "kvm", or "hyperv"
   Returns 0 on success, -1 on failure.
   Windows only; returns -1 on other platforms. */
int agent_install(const char *profile_name, const char *platform_name);

/* Remove the scheduled hardening task and its config file.
   Returns 0 on success, -1 on failure. */
int agent_remove(void);

/* Check whether the agent task is currently installed.
   Returns 1 if installed, 0 if not, -1 on error. */
int agent_is_installed(void);
