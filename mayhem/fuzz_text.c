/*
 * Text/path harness: untrusted strings handed to PhysicsFS's public API. Byte 0 selects the operation;
 * the rest is the string. Covers the UTF-8/UCS-2/UCS-4/UTF-16/Latin-1 converters and case-insensitive
 * comparers, and the virtual-path sanitiser (PHYSFS_stat/exists/openRead/enumerate/getRealDir) against
 * a small read-only GRP archive that is mounted once at startup; every input leaves the search path as it found it.
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "physfs.h"

static void le32(uint8_t *p, uint32_t v)
{
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}

static uint8_t grp[12 + 4 + 2 * 16 + 5 + 3];

static void build_grp(void)
{
    uint8_t *p = grp;
    memcpy(p, "KenSilverman", 12); p += 12;
    le32(p, 2); p += 4;
    memcpy(p, "HELLO.TXT\0\0\0", 12); le32(p + 12, 5); p += 16;
    memcpy(p, "B.DAT\0\0\0\0\0\0\0", 12); le32(p + 12, 3); p += 16;
    memcpy(p, "world", 5); p += 5;
    memcpy(p, "abc", 3);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc;
    if (!PHYSFS_init((*argv)[0]))
        abort();
    build_grp();
    if (!PHYSFS_mountMemory(grp, sizeof (grp), NULL, "base.grp", NULL, 1))
        abort();
    if (!PHYSFS_mountMemory(grp, sizeof (grp), NULL, "sub.grp", "dir/sub", 1))
        abort();
    return 0;
}

static PHYSFS_EnumerateCallbackResult cb(void *d, const char *o, const char *f)
{
    (void) d; (void) o; (void) f;
    return PHYSFS_ENUM_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t op;
    size_t n;
    char *s, *t;

    if (size < 1)
        return -1;
    op = data[0] % 12;
    n = size - 1;

    s = (char *) malloc(n + 4);
    if (!s)
        abort();
    memcpy(s, data + 1, n);
    memset(s + n, 0, 4);

    switch (op)
    {
        case 0: {  /* UTF-8 -> UCS-4 / UCS-2 / UTF-16 (src: NUL-terminated UTF-8) */
            uint32_t *d4 = (uint32_t *) malloc((n + 1) * sizeof (uint32_t));
            uint16_t *d2 = (uint16_t *) malloc((n + 1) * sizeof (uint16_t));
            uint16_t *d16 = (uint16_t *) malloc((n + 1) * sizeof (uint16_t));
            PHYSFS_utf8ToUcs4(s, d4, (n + 1) * sizeof (uint32_t));
            PHYSFS_utf8ToUcs2(s, d2, (n + 1) * sizeof (uint16_t));
            PHYSFS_utf8ToUtf16(s, d16, (n + 1) * sizeof (uint16_t));
            free(d4); free(d2); free(d16);
            break;
        }
        case 1: {  /* UCS-4 -> UTF-8 (src: NUL-terminated uint32 array); worst case 4 bytes/unit */
            size_t units = n / 4 + 1;
            uint32_t *src = (uint32_t *) calloc(units, sizeof (uint32_t));
            char *dst = (char *) malloc(units * 4 + 1);
            memcpy(src, s, (n / 4) * 4);
            PHYSFS_utf8FromUcs4(src, dst, units * 4 + 1);
            free(src); free(dst);
            break;
        }
        case 2: {  /* UCS-2 -> UTF-8 */
            size_t units = n / 2 + 1;
            uint16_t *src = (uint16_t *) calloc(units, sizeof (uint16_t));
            char *dst = (char *) malloc(units * 3 + 1);
            memcpy(src, s, (n / 2) * 2);
            PHYSFS_utf8FromUcs2(src, dst, units * 3 + 1);
            free(src); free(dst);
            break;
        }
        case 3: {  /* UTF-16 -> UTF-8 */
            size_t units = n / 2 + 1;
            uint16_t *src = (uint16_t *) calloc(units, sizeof (uint16_t));
            char *dst = (char *) malloc(units * 4 + 1);
            memcpy(src, s, (n / 2) * 2);
            PHYSFS_utf8FromUtf16(src, dst, units * 4 + 1);
            free(src); free(dst);
            break;
        }
        case 4: {  /* Latin-1 -> UTF-8 */
            char *dst = (char *) malloc(n * 2 + 1);
            PHYSFS_utf8FromLatin1(s, dst, n * 2 + 1);
            free(dst);
            break;
        }
        case 5: {  /* case-insensitive UTF-8 compare of the two halves split at the first NUL/midpoint */
            size_t half = n / 2;
            s[half] = '\0';
            t = (char *) malloc(n - half + 1);
            memcpy(t, data + 1 + half, n - half);
            t[n - half] = '\0';
            (void) PHYSFS_utf8stricmp(s, t);
            free(t);
            break;
        }
        case 6: {  /* case-insensitive UCS-4 compare */
            size_t units = n / 8 + 1;
            uint32_t *a = (uint32_t *) calloc(units + 1, sizeof (uint32_t));
            uint32_t *b = (uint32_t *) calloc(units + 1, sizeof (uint32_t));
            memcpy(a, s, (n / 8) * 4);
            memcpy(b, s + (n / 8) * 4, (n / 8) * 4);
            (void) PHYSFS_ucs4stricmp(a, b);
            free(a); free(b);
            break;
        }
        case 7: {  /* virtual path -> stat / exists / real dir / mount point */
            PHYSFS_Stat st;
            (void) PHYSFS_stat(s, &st);
            (void) PHYSFS_exists(s);
            (void) PHYSFS_getRealDir(s);
            (void) PHYSFS_getMountPoint(s);
            break;
        }
        case 8: {  /* virtual path -> open + read */
            PHYSFS_File *f = PHYSFS_openRead(s);
            if (f)
            {
                char buf[64];
                (void) PHYSFS_fileLength(f);
                (void) PHYSFS_readBytes(f, buf, sizeof (buf));
                PHYSFS_close(f);
            }
            break;
        }
        case 9: {  /* virtual path -> enumerate */
            char **list = PHYSFS_enumerateFiles(s);
            if (list)
                PHYSFS_freeList(list);
            (void) PHYSFS_enumerate(s, cb, NULL);
            break;
        }
        case 10: {  /* path used as the mount point of an archive; unmounted again */
            if (PHYSFS_mountMemory(grp, sizeof (grp), NULL, "tmp.grp", s, 1))
            {
                char **list = PHYSFS_enumerateFiles("");
                if (list)
                    PHYSFS_freeList(list);
                (void) PHYSFS_unmount("tmp.grp");
            }
            break;
        }
        default: {  /* path used as the archive's own name (extension dispatch) */
            /* doMount() returns 1 without mounting when the name is already in the search path, so only
               unmount what this input mounted; the startup mounts must survive every input. */
            if (PHYSFS_getMountPoint(s) == NULL && PHYSFS_mountMemory(grp, sizeof (grp), NULL, s, NULL, 1))
                (void) PHYSFS_unmount(s);
            break;
        }
    }
    free(s);
    return 0;
}
