#pragma once

struct reg_artifact {
    char path[256];
    char description[128];
};

struct fs_artifact {
    char path[260];
    char description[128];
};

int detect_registry_artifacts(struct reg_artifact results[], int max_results);
int detect_filesystem_artifacts(struct fs_artifact results[], int max_results);
