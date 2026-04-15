#pragma once

#include <stdbool.h>
#include <stddef.h>

#define RB_MAX_ENTRIES  128
#define RB_PATH_MAX     512
#define RB_DESC_MAX     256

/* Types of reversible actions the rollback system can undo. */
typedef enum {
    RB_ACTION_REG_DELETE_KEY,   /* registry key was deleted; backup .dat exists   */
    RB_ACTION_FS_RENAME,        /* file was renamed (target=new, backup=original) */
    RB_ACTION_MAC_CHANGE,       /* MAC address was spoofed; backup=original MAC   */
    RB_ACTION_SERVICE_DISABLE,  /* service was stopped+disabled                   */
    RB_ACTION_DRIVER_DISABLE,   /* driver-type service was disabled               */
    RB_ACTION_BIOS_SPOOF        /* BIOS registry values were spoofed              */
} rollback_action_type;

/* One reversible action. */
typedef struct {
    rollback_action_type type;
    char target[RB_PATH_MAX];   /* what was changed (reg path, file path, adapter) */
    char backup[RB_PATH_MAX];   /* how to restore  (backup file, original name)    */
    char description[RB_DESC_MAX];
} rollback_entry;

/* Collection of entries saved together after one remediation run. */
typedef struct {
    char timestamp[32];               /* "YYYY-MM-DD HH:MM:SS" */
    char profile[64];                 /* profile name or "manual" */
    rollback_entry entries[RB_MAX_ENTRIES];
    int  count;
} rollback_manifest;

/* Initialise an empty manifest with current timestamp and profile name. */
void rollback_init(rollback_manifest *m, const char *profile_name);

/* Append one entry.  Returns 0 on success, -1 if manifest is full. */
int  rollback_add_entry(rollback_manifest *m,
                        rollback_action_type type,
                        const char *target,
                        const char *backup,
                        const char *desc);

/* Persist manifest to a JSON file.  Returns 0 on success. */
int  rollback_save(const rollback_manifest *m, const char *filepath);

/* Load manifest from a JSON file.   Returns 0 on success. */
int  rollback_load(rollback_manifest *m, const char *filepath);

/* Execute all entries in reverse order, restoring original state.
   If verbose is true, prints each step to stdout.
   Returns the number of successfully restored entries (negative on fatal error). */
int  rollback_execute(const rollback_manifest *m, bool verbose);

/* Generate a timestamped filename like "logs/rollback_YYYY-MM-DD_HH-MM-SS.json".
   Writes into buf (at most size bytes). */
void rollback_make_filename(char *buf, size_t size);
