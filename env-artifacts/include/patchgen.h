#pragma once

#include "interactive.h"
#include "tips.h"
#include <stddef.h>

/* Generate a host-side config patch file for the given platform.
   Writes to a timestamped file in logs/ and stores the path in out_path.
   Returns 0 on success. */
int patchgen_generate(const scan_snapshot *snap,
                      hypervisor_platform platform,
                      char *out_path, size_t out_path_size);

/* Write patch content to an already-open FILE stream.
   Reusable for stdout or file output. */
void patchgen_write(const scan_snapshot *snap,
                    hypervisor_platform platform,
                    FILE *fp);

/* Print patch content to stdout (preview mode). */
void patchgen_preview(const scan_snapshot *snap,
                      hypervisor_platform platform);
