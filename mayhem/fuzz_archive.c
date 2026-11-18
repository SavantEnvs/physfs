/*
 * Archive-mount harness: the input is an archive image handed to PhysicsFS's public mount API
 * (PHYSFS_mountMemory). Byte 0 picks the file extension the archive is "named" with (PhysicsFS tries
 * the archiver matching the extension first, then all the others) and whether it is mounted under a
 * sub-directory; the rest is the archive. After a successful mount the whole tree is enumerated, and
 * every file is stat'ed, opened, read (decompressed), sought in and closed.
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "physfs.h"

static const char *const exts[] = {
    "7z", "bin", "grp", "hog", "iso", "gob", "lab", "lfd", "mvl",
    "pod", "pak", "rofs", "slb", "vdf", "wad", "zip", "",
};
#define NEXTS ((int) (sizeof (exts) / sizeof (exts[0])))

#define MAX_DEPTH 32
#define MAX_FILES 256
#define MAX_READ_PER_FILE (1 << 20)

typedef struct
{
    int depth;
    int files;
} WalkState;

static PHYSFS_EnumerateCallbackResult walk(void *data, const char *origdir, const char *fname)
{
    WalkState *st = (WalkState *) data;
    char path[4096];
    PHYSFS_Stat stat;
    int n;

    if (st->files >= MAX_FILES)
        return PHYSFS_ENUM_STOP;
    st->files++;

    n = snprintf(path, sizeof (path), "%s%s%s", origdir, (*origdir ? "/" : ""), fname);
    if (n < 0 || (size_t) n >= sizeof (path))
        return PHYSFS_ENUM_OK;

    if (!PHYSFS_stat(path, &stat))
        return PHYSFS_ENUM_OK;

    if (stat.filetype == PHYSFS_FILETYPE_DIRECTORY)
    {
        if (st->depth < MAX_DEPTH)
        {
            st->depth++;
            PHYSFS_enumerate(path, walk, st);
            st->depth--;
        }
    }
    else if (stat.filetype == PHYSFS_FILETYPE_REGULAR)
    {
        PHYSFS_File *f = PHYSFS_openRead(path);
        if (f)
        {
            static char buf[4096];
            PHYSFS_sint64 len = PHYSFS_fileLength(f);
            PHYSFS_sint64 total = 0, got;

            while (total < MAX_READ_PER_FILE && (got = PHYSFS_readBytes(f, buf, sizeof (buf))) > 0)
                total += got;

            if (len > 1 && PHYSFS_seek(f, (PHYSFS_uint64) len / 2))
            {
                (void) PHYSFS_tell(f);
                (void) PHYSFS_readBytes(f, buf, sizeof (buf));
                (void) PHYSFS_eof(f);
            }
            PHYSFS_close(f);
        }
    }
    return PHYSFS_ENUM_OK;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc;
    if (!PHYSFS_init((*argv)[0]))
        abort();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char name[16];
    const char *mnt;
    WalkState st = {0, 0};
    uint8_t sel;

    if (size < 2)
        return -1;

    sel = data[0];
    snprintf(name, sizeof (name), "archive.%s", exts[(sel & 0x7f) % NEXTS]);
    if (name[sizeof ("archive.") - 1] == '\0')
        name[sizeof ("archive.") - 2] = '\0';  /* extensionless: no trailing dot */
    mnt = (sel & 0x80) ? "mnt/sub" : NULL;

    if (PHYSFS_mountMemory(data + 1, size - 1, NULL, name, mnt, 1))
    {
        PHYSFS_enumerate("", walk, &st);
        (void) PHYSFS_getMountPoint(name);
        (void) PHYSFS_unmount(name);
    }
    return 0;
}
