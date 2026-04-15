#pragma once

/**
 * Populates buf with a human-readable OS version string.
 * Example: "Windows 11 23H2 (Build 26200)"
 * Non-Windows: "Non-Windows OS"
 */
void get_os_version_string(char *buf, int buf_size);
