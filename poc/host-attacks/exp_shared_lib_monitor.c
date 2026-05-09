/*
 * Copy Fail — Shared library live-patching monitor
 *
 * Loads libnss_files.so via dlopen and continuously reads the
 * "/etc/hosts" string from its .rodata section to observe page
 * cache modifications in real time, WITHOUT restarting.
 *
 * Build:  gcc -o monitor exp_shared_lib_monitor.c -ldl
 * Usage:  ./monitor [/path/to/libnss_files.so] [interval_sec]
 *
 * Run this FIRST, then run exp_shared_lib.py in another terminal.
 * The monitor will print when it detects the string change.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>

#define DEFAULT_SO    "/usr/lib64/libnss_files-2.28.so"
#define TARGET_STRING "/etc/hosts"
#define MAX_TICKS     60

static const char *find_string(void *handle, const char *target) {
    /*
     * Walk the loaded .so image to find the target string.
     * We use dlsym to get a known symbol, then scan nearby memory.
     * Alternative: parse /proc/self/maps for the library base.
     */
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return NULL;

    char line[512];
    unsigned long base = 0, end = 0;
    const char *so_path = DEFAULT_SO;

    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libnss_files") && strstr(line, "r-")) {
            sscanf(line, "%lx-%lx", &base, &end);
            break;
        }
    }
    fclose(maps);

    if (!base) return NULL;

    for (unsigned long addr = base; addr < end - strlen(target); addr++) {
        if (memcmp((void *)addr, target, strlen(target)) == 0)
            return (const char *)addr;
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    const char *so_path = argc > 1 ? argv[1] : DEFAULT_SO;
    int interval = argc > 2 ? atoi(argv[2]) : 1;

    void *handle = dlopen(so_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "[-] dlopen failed: %s\n", dlerror());
        return 1;
    }

    const char *ptr = find_string(handle, TARGET_STRING);
    if (!ptr) {
        fprintf(stderr, "[-] Could not find '%s' in loaded library\n", TARGET_STRING);
        dlclose(handle);
        return 1;
    }

    char initial[32] = {0};
    strncpy(initial, ptr, sizeof(initial) - 1);
    printf("[monitor] PID=%d\n", getpid());
    printf("[monitor] initial: \"%s\" at %p\n", initial, ptr);

    for (int tick = 1; tick <= MAX_TICKS; tick++) {
        sleep(interval);
        if (strncmp(ptr, initial, strlen(initial)) != 0) {
            printf("[monitor] tick %d: *** STRING CHANGED ***\n", tick);
            printf("[monitor] now: \"%.*s\"\n", (int)strlen(TARGET_STRING), ptr);
            printf("[monitor] *** LIVE-PATCH CONFIRMED (no restart) ***\n");
        } else {
            printf("[monitor] tick %d: no change\n", tick);
        }
    }

    dlclose(handle);
    return 0;
}
