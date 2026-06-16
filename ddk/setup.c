#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <libgen.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <regex.h>

#define MAX_PATH 4096
#define MAX_BUFFER 8192
#define ERROR_DIR_NOT_FOUND 127
#define ERROR_GENERAL 1

typedef struct {
    char gki_root[MAX_PATH];
    char script_dir[MAX_PATH];
    char src_dir[MAX_PATH];
    char patch_dir[MAX_PATH];
    char ddk_dir[MAX_PATH];
    char common_root[MAX_PATH];
    char security_dir[MAX_PATH];
    char security_makefile[MAX_PATH];
    char security_kconfig[MAX_PATH];
    char ddk_symlink[MAX_PATH];
} DDKConfig;

// Get current working directory
int get_pwd(char *buffer, size_t size) {
    if (getcwd(buffer, size) == NULL) {
        perror("getcwd");
        return -1;
    }
    return 0;
}

// Get script directory
int get_script_dir(const char *argv0, char *buffer, size_t size) {
    char path[MAX_PATH];
    char *dir;
    
    if (realpath(argv0, path) == NULL) {
        perror("realpath");
        return -1;
    }
    
    dir = dirname(path);
    if (strlen(dir) >= size) {
        fprintf(stderr, "Script directory path too long\n");
        return -1;
    }
    
    strcpy(buffer, dir);
    return 0;
}

// Check if directory exists
int dir_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) ? 1 : 0;
}

// Check if file exists
int file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode)) ? 1 : 0;
}

// Initialize configuration
int init_config(const char *argv0, DDKConfig *config) {
    if (get_pwd(config->gki_root, MAX_PATH) != 0) {
        return -1;
    }
    
    if (get_script_dir(argv0, config->script_dir, MAX_PATH) != 0) {
        return -1;
    }
    
    // Build paths
    snprintf(config->src_dir, MAX_PATH, "%s/xingguang-ddk", config->script_dir);
    snprintf(config->patch_dir, MAX_PATH, "%s/patches/xingguang-ddk", config->script_dir);
    snprintf(config->ddk_dir, MAX_PATH, "%s/Xingguang-DDK", config->gki_root);
    
    // Determine security directory
    char security_test[MAX_PATH];
    snprintf(security_test, MAX_PATH, "%s/security", config->gki_root);
    
    if (dir_exists(security_test)) {
        strcpy(config->common_root, config->gki_root);
        snprintf(config->security_dir, MAX_PATH, "%s/security", config->gki_root);
    } else {
        snprintf(security_test, MAX_PATH, "%s/common/security", config->gki_root);
        if (dir_exists(security_test)) {
            snprintf(config->common_root, MAX_PATH, "%s/common", config->gki_root);
            snprintf(config->security_dir, MAX_PATH, "%s/common/security", config->gki_root);
        } else {
            fprintf(stderr, "[ERROR] security directory not found.\n");
            return ERROR_DIR_NOT_FOUND;
        }
    }
    
    snprintf(config->security_makefile, MAX_PATH, "%s/Makefile", config->security_dir);
    snprintf(config->security_kconfig, MAX_PATH, "%s/Kconfig", config->security_dir);
    snprintf(config->ddk_symlink, MAX_PATH, "%s/xingguang-ddk", config->security_dir);
    
    return 0;
}

// Check if file contains a regex pattern
int file_contains_pattern(const char *filepath, const char *pattern) {
    FILE *fp;
    char line[MAX_BUFFER];
    regex_t regex;
    int ret = 0;
    
    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
        fprintf(stderr, "Failed to compile regex: %s\n", pattern);
        return 0;
    }
    
    fp = fopen(filepath, "r");
    if (fp == NULL) {
        regfree(&regex);
        return 0;
    }
    
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (regexec(&regex, line, 0, NULL, 0) == 0) {
            ret = 1;
            break;
        }
    }
    
    fclose(fp);
    regfree(&regex);
    return ret;
}

// Read entire file into memory
char* read_file(const char *filepath, size_t *size) {
    FILE *fp;
    char *buffer;
    size_t file_size;
    
    fp = fopen(filepath, "rb");
    if (fp == NULL) {
        perror("fopen");
        return NULL;
    }
    
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    buffer = malloc(file_size + 1);
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(fp);
        return NULL;
    }
    
    if (fread(buffer, 1, file_size, fp) != file_size) {
        fprintf(stderr, "Failed to read file\n");
        free(buffer);
        fclose(fp);
        return NULL;
    }
    
    buffer[file_size] = '\0';
    *size = file_size;
    
    fclose(fp);
    return buffer;
}

// Write buffer to file
int write_file(const char *filepath, const char *buffer, size_t size) {
    FILE *fp;
    
    fp = fopen(filepath, "wb");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }
    
    if (fwrite(buffer, 1, size, fp) != size) {
        fprintf(stderr, "Failed to write file\n");
        fclose(fp);
        return -1;
    }
    
    fclose(fp);
    return 0;
}

// Execute system command with error checking
int exec_git_apply(const char *repo_dir, const char *patch_file, int check_only) {
    char cmd[MAX_BUFFER * 2];
    int ret;
    
    if (check_only) {
        snprintf(cmd, sizeof(cmd), "git -C \"%s\" apply --check \"%s\" >/dev/null 2>&1", repo_dir, patch_file);
    } else {
        snprintf(cmd, sizeof(cmd), "git -C \"%s\" apply \"%s\"", repo_dir, patch_file);
    }
    
    ret = system(cmd);
    return ret;
}

// Check if patch is already applied (reverse check)
int patch_already_applied(const char *repo_dir, const char *patch_file) {
    char cmd[MAX_BUFFER * 2];
    snprintf(cmd, sizeof(cmd), "git -C \"%s\" apply --reverse --check \"%s\" >/dev/null 2>&1", repo_dir, patch_file);
    return (system(cmd) == 0) ? 1 : 0;
}

// Apply patches from directory
int apply_patches(const char *patch_dir, const char *common_root) {
    DIR *dir;
    struct dirent *entry;
    char patch_file[MAX_PATH];
    char patch_name[256];
    int optional;
    
    dir = opendir(patch_dir);
    if (dir == NULL) {
        perror("opendir");
        return -1;
    }
    
    printf("[+] Applying Xingguang DDK patch stack\n");
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) continue;
        if (strstr(entry->d_name, ".patch") == NULL) continue;
        
        snprintf(patch_file, MAX_PATH, "%s/%s", patch_dir, entry->d_name);
        strcpy(patch_name, entry->d_name);
        
        optional = (strstr(patch_name, ".optional.patch") != NULL) ? 1 : 0;
        
        // Try normal apply
        if (exec_git_apply(common_root, patch_file, 1) == 0) {
            exec_git_apply(common_root, patch_file, 0);
            printf(" - applied %s\n", patch_name);
            continue;
        }
        
        // Check if already applied
        if (patch_already_applied(common_root, patch_file)) {
            printf(" - already applied %s\n", patch_name);
            continue;
        }
        
        // Handle optional patches
        if (optional) {
            printf(" - skipped optional %s\n", patch_name);
            continue;
        }
        
        // Failed to apply
        fprintf(stderr, "[ERROR] failed to apply DDK patch: %s\n", patch_file);
        closedir(dir);
        return ERROR_GENERAL;
    }
    
    closedir(dir);
    return 0;
}

// Copy directory recursively (simplified version)
int copy_directory(const char *src, const char *dst) {
    char cmd[MAX_BUFFER * 2];
    
    snprintf(cmd, sizeof(cmd), "cp -a \"%s/.\" \"%s/\"", src, dst);
    
    if (system(cmd) != 0) {
        fprintf(stderr, "[ERROR] Failed to copy directory from %s to %s\n", src, dst);
        return ERROR_GENERAL;
    }
    
    return 0;
}

// Remove directory recursively
int remove_directory(const char *path) {
    char cmd[MAX_BUFFER];
    snprintf(cmd, sizeof(cmd), "rm -rf \"%s\"", path);
    return system(cmd);
}

// Create symlink
int create_symlink(const char *target, const char *link_path) {
    char cmd[MAX_BUFFER * 2];
    snprintf(cmd, sizeof(cmd), "ln -sfn \"%s\" \"%s\"", target, link_path);
    return system(cmd);
}

// Update Makefile with DDK configuration
int update_makefile(const char *makefile_path) {
    char *content;
    size_t size;
    char new_content[MAX_BUFFER * 2];
    
    if (!file_exists(makefile_path)) {
        fprintf(stderr, "[ERROR] Makefile not found: %s\n", makefile_path);
        return -1;
    }
    
    content = read_file(makefile_path, &size);
    if (content == NULL) {
        return -1;
    }
    
    if (strstr(content, "xingguang-ddk") == NULL) {
        snprintf(new_content, sizeof(new_content), "%s\nobj-$(CONFIG_XINGGUANG_DDK) += xingguang-ddk/\n", content);
        if (write_file(makefile_path, new_content, strlen(new_content)) != 0) {
            free(content);
            return -1;
        }
        printf(" - Makefile updated\n");
    }
    
    free(content);
    return 0;
}

// Update Kconfig with DDK configuration
int update_kconfig(const char *kconfig_path) {
    char *content;
    size_t size;
    char new_content[MAX_BUFFER * 4];
    const char *insert_line = "source \"security/xingguang-ddk/Kconfig\"\n";
    
    if (!file_exists(kconfig_path)) {
        fprintf(stderr, "[ERROR] Kconfig not found: %s\n", kconfig_path);
        return -1;
    }
    
    content = read_file(kconfig_path, &size);
    if (content == NULL) {
        return -1;
    }
    
    if (strstr(content, "security/xingguang-ddk/Kconfig") == NULL) {
        char *endmenu_pos = strstr(content, "\nendmenu");
        
        if (endmenu_pos != NULL) {
            size_t prefix_len = endmenu_pos - content + 1;
            snprintf(new_content, sizeof(new_content), "%.*s%s%s", 
                    (int)prefix_len, content, insert_line, endmenu_pos + 1);
        } else {
            snprintf(new_content, sizeof(new_content), "%s\n%s", content, insert_line);
        }
        
        if (write_file(kconfig_path, new_content, strlen(new_content)) != 0) {
            free(content);
            return -1;
        }
        printf(" - Kconfig updated\n");
    }
    
    free(content);
    return 0;
}

// Main setup function
int ddk_setup(const char *argv0) {
    DDKConfig config;
    int ret;
    
    printf("[+] Setting up Xingguang DDK LSM\n");
    
    // Initialize configuration
    if ((ret = init_config(argv0, &config)) != 0) {
        return ret;
    }
    
    // Check if source directory exists
    if (!dir_exists(config.src_dir)) {
        fprintf(stderr, "[ERROR] DDK source directory not found: %s\n", config.src_dir);
        return ERROR_DIR_NOT_FOUND;
    }
    
    // Apply patches if patch directory exists
    if (dir_exists(config.patch_dir)) {
        if ((ret = apply_patches(config.patch_dir, config.common_root)) != 0) {
            return ret;
        }
    }
    
    // Remove old DDK directory and copy new one
    remove_directory(config.ddk_dir);
    if (mkdir(config.ddk_dir, 0755) != 0 && errno != EEXIST) {
        perror("mkdir");
        return ERROR_GENERAL;
    }
    
    if (copy_directory(config.src_dir, config.ddk_dir) != 0) {
        return ERROR_GENERAL;
    }
    
    // Create symlink
    if (chdir(config.security_dir) != 0) {
        perror("chdir");
        return ERROR_GENERAL;
    }
    
    char rel_path[MAX_PATH];
    char cmd[MAX_BUFFER];
    
    snprintf(cmd, sizeof(cmd), "realpath --relative-to=\"%s\" \"%s\" 2>/dev/null", 
             config.security_dir, config.ddk_dir);
    
    FILE *fp = popen(cmd, "r");
    if (fp != NULL) {
        if (fgets(rel_path, sizeof(rel_path), fp) != NULL) {
            size_t len = strlen(rel_path);
            if (len > 0 && rel_path[len-1] == '\n') {
                rel_path[len-1] = '\0';
            }
        }
        pclose(fp);
    }
    
    if (strlen(rel_path) == 0) {
        strcpy(rel_path, config.ddk_dir);
    }
    
    if (create_symlink(rel_path, config.ddk_symlink) != 0) {
        fprintf(stderr, "[ERROR] Failed to create symlink\n");
        return ERROR_GENERAL;
    }
    
    // Update Makefile and Kconfig
    if (update_makefile(config.security_makefile) != 0) {
        return ERROR_GENERAL;
    }
    
    if (update_kconfig(config.security_kconfig) != 0) {
        return ERROR_GENERAL;
    }
    
    printf("[+] Xingguang DDK LSM ready.\n");
    
    return 0;
}

int main(int argc, char *argv[]) {
    int ret;
    
    if (argc < 1) {
        fprintf(stderr, "Usage: %s\n", argv[0]);
        return ERROR_GENERAL;
    }
    
    ret = ddk_setup(argv[0]);
    
    return ret;
}
