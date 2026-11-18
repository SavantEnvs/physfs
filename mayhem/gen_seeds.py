#!/usr/bin/env python3
"""Regenerates mayhem/fuzz_archive/testsuite/*: a small valid archive per format, prefixed with the
harness's selector byte (index into the extension table in fuzz_archive.c). Not run by the build."""
import io, os, struct, sys, zipfile

EXTS = ["7z", "bin", "grp", "hog", "iso", "gob", "lab", "lfd", "mvl", "pod", "pak", "rofs", "slb", "vdf", "wad", "zip", ""]
FILES = [("HELLO.TXT", b"hello world\n" * 3), ("DATA.BIN", bytes(range(64)))]
u32 = lambda v: struct.pack("<I", v)


def pad(b, n):
    return b[:n].ljust(n, b"\0")


def grp():
    out = b"KenSilverman" + u32(len(FILES)) + b"".join(pad(n.encode(), 12) + u32(len(d)) for n, d in FILES)
    return out + b"".join(d for _, d in FILES)


def wad():
    body = b"".join(d for _, d in FILES)
    off, ent = 12, b""
    for n, d in FILES:
        ent += u32(off) + u32(len(d)) + pad(n.encode(), 8)
        off += len(d)
    return b"PWAD" + u32(len(FILES)) + u32(12 + len(body)) + body + ent


def hog():
    return b"DHF" + b"".join(pad(n.encode(), 13) + u32(len(d)) + d for n, d in FILES)


def mvl():
    return b"DMVL" + u32(len(FILES)) + b"".join(pad(n.encode(), 13) + u32(len(d)) for n, d in FILES) + b"".join(d for _, d in FILES)


def qpak():
    # the archiver consumes 68 bytes per directory entry (name[56], pos, size, size) but takes the
    # directory length as count*64, so the directory goes first and the data after it
    n = len(FILES)
    off, ent = 12 + 68 * n, b""
    for name, d in FILES:
        ent += pad(name.encode(), 56) + u32(off) + u32(len(d)) + u32(len(d))
        off += len(d)
    return b"PACK" + u32(12) + u32(64 * n) + ent + b"".join(d for _, d in FILES)


def csm():
    ent, off = b"", 6 + 21 * len(FILES)
    for n, d in FILES:
        ent += bytes([min(len(n), 12)]) + pad(n.encode(), 12) + u32(len(d)) + u32(off)
        off += len(d)
    return b"CSid" + struct.pack("<H", len(FILES)) + ent + b"".join(d for _, d in FILES)


def pod():
    hdr = u32(len(FILES)) + pad(b"seed pod", 80)
    off, ent = 84 + 40 * len(FILES), b""
    for n, d in FILES:
        ent += pad(n.encode(), 32) + u32(len(d)) + u32(off)
        off += len(d)
    return hdr + ent + b"".join(d for _, d in FILES)


def vdf():
    sig = b"PSVDSC_V2.00\n\r\n\r"
    comment = pad(b"seed vdf\x1a", 256)
    cat_off = 296
    ents, off = b"", cat_off + 80 * len(FILES)
    for n, d in FILES:
        ents += pad(n.encode().ljust(64, b" "), 64) + u32(off) + u32(len(d)) + u32(0) + u32(0)
        off += len(d)
    hdr = comment + sig + u32(len(FILES)) + u32(len(FILES)) + u32(0) + u32(off) + u32(cat_off) + u32(0x50)
    return pad(hdr, cat_off) + ents + b"".join(d for _, d in FILES)


def zipf(method):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", method) as z:
        z.writestr("top.txt", b"zip seed " * 40)
        z.writestr("sub/inner.bin", bytes(range(256)) * 2)
        z.writestr("sub/deeper/", b"")
    return b.getvalue()


SEEDS = {
    "grp": ("grp", grp()), "wad": ("wad", wad()), "hog": ("hog", hog()), "mvl": ("mvl", mvl()),
    "qpak": ("pak", qpak()), "csm": ("bin", csm()), "pod": ("pod", pod()), "vdf": ("vdf", vdf()),
    "zip_deflate": ("zip", zipf(zipfile.ZIP_DEFLATED)), "zip_stored": ("zip", zipf(zipfile.ZIP_STORED)),
    "zip_noext": ("", zipf(zipfile.ZIP_DEFLATED)), "grp_mounted": ("grp", grp()),
}

out = sys.argv[1] if len(sys.argv) > 1 else "mayhem/fuzz_archive/testsuite"
os.makedirs(out, exist_ok=True)
for name, (ext, data) in SEEDS.items():
    sel = EXTS.index(ext) | (0x80 if name == "grp_mounted" else 0)
    with open(os.path.join(out, name), "wb") as f:
        f.write(bytes([sel]) + data)
