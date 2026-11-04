#!/usr/bin/env python3
"""readset_fuse.py — a FUSE permit tree that records which pages of the served
files were actually READ, and emits a receipt a stranger can recompute.

Why this exists
---------------
read-trace-witness (2026-11-03) measured that ptrace, inotify and atime produce
identical records for a file that was mmap'd and fully consumed and one that was
mmap'd and never dereferenced. So no *passive* witness at the seat's privilege
level can say "the bytes became input".

A FUSE daemon is not a passive witness: it is the filesystem. The kernel cannot
deliver a page of this file to a process without sending this process a READ
request. The read-set is therefore recorded where the read happens, not where it
is observed.

What it records, exactly
----------------------------
One JSONL line per READ the kernel asked for:

    {"seq":1,"nodeid":2,"off":0,"len":4096,"sha256":"...","kind":"read"}

plus a receipt header with the fixture hash, the mount options and the verdict.
`kind` is guessed from the request shape and is INFORMATIONAL — the receipt's
claim never depends on it:
  * a request that starts and ends on page boundaries with len == page size is
    consistent with a page-fault fill, which is what mmap produces;
  * a short, unaligned request is consistent with a read(2)/sendfile pass.

THE BOUND, stated rather than implied
-------------------------------------
The kernel page cache sits between the daemon and the caller. A page already
cached is not re-requested, so this receipt is a record of *pages the daemon was
asked to deliver*, not of bytes the caller consumed:

  * for a file served in one page, one `mmap` fault and a full `read(2)` produce
    the SAME single READ request. The witness distinguishes "touched at least
    one page" from "touched no page", not "read 64 of 64 bytes" from "read 32".
  * a second read of the same page produces no new line.

That is the honest claim: page-granular read-set membership. It is exactly the
granularity the card asks for, and it is the granularity that closes the
2026-11-03 gap, because "mapped but never dereferenced" produces ZERO pages.

Protocol: raw /dev/fuse, no libfuse binding, no compilation. Only the message
layout in fuse_kernel.h.
"""

import errno
import hashlib
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import time

PAGE = 4096

# ---------------------------------------------------------------- structures

IN_HDR = struct.Struct("<IIQQIIII")          # 40 bytes
OUT_HDR = struct.Struct("<IiQ")              # 16 bytes
ATTR = struct.Struct("<QQQQQQIIIIIIIIII")    # 88 bytes: fuse_attr
# fuse_attr_out { u64 attr_valid; u32 attr_valid_nsec; u32 dummy; fuse_attr } -> 16 + 88
# sizeof(struct fuse_attr_out) == 104, measured with a C probe against
# /usr/include/linux/fuse.h — not derived from the field names, which is how the
# 12-byte version (u32 attr_valid) got written and made every GETATTR reply
# EINVAL: the kernel rejects a short reply by aborting the mount, so the failure
# looks like a dead daemon rather than a malformed struct.
ATTR_OUT = struct.Struct("<QII")
# fuse_entry_out { u64 nodeid; u64 generation; u64 entry_valid; u64 attr_valid;
#                  u32 entry_valid_nsec; u32 attr_valid_nsec; fuse_attr } -> 128
ENTRY = struct.Struct("<QQQQII")
# fuse_open_out { u64 fh; u32 open_flags; u32 padding } -> 16
OPEN_OUT = struct.Struct("<QII")

# Opcodes copied from `enum fuse_opcode` in /usr/include/linux/fuse.h (7.45).
# The first version of this file carried a hand-typed table that was off by one
# from FUSE_OPEN (=14) onward: the daemon answered a READ as if it were an OPEN,
# the kernel rejected the 16-byte reply to a 40-byte request, and the abort
# surfaced as "Transport endpoint is not connected". Every table of constants
# transcribed by eye is a second implementation of the header.
FUSE_LOOKUP = 1
FUSE_FORGET = 2
FUSE_GETATTR = 3
FUSE_SETATTR = 4
FUSE_OPEN = 14
FUSE_READ = 15
FUSE_WRITE = 16
FUSE_STATFS = 17
FUSE_RELEASE = 18
FUSE_GETXATTR = 22
FUSE_LISTXATTR = 23
FUSE_FLUSH = 25
FUSE_INIT = 26
FUSE_OPENDIR = 27
FUSE_READDIR = 28
FUSE_RELEASEDIR = 29
FUSE_ACCESS = 34
FUSE_DESTROY = 38
FUSE_BATCH_FORGET = 42
FUSE_READDIRPLUS = 44
FUSE_STATX = 52

ROOT_NODE = 1
PAGE_ALIGNED = "page-fault-fill"
OTHER = "read-fill"


def attr_block(ino, size, mode, nlink=1):
    return ATTR.pack(
        ino, size, (size + 511) // 512,
        0, 0, 0,                      # atime, mtime, ctime (deliberately zero: a
                                      # witness that reports a timestamp invites
                                      # the atime conflation this instrument exists
                                      # to rule out)
        0, 0, 0,                      # nsec fields
        mode, nlink, os.getuid(), os.getgid(),
        0, PAGE, 0,
    )


# ---------------------------------------------------------------- the daemon

class ReadSetFS:
    """One directory, a fixed set of read-only files, one JSONL receipt."""

    def __init__(self, files, receipt_path):
        # files: {name: bytes}. nodeid 1 is the root dir, files start at 2.
        self.nodes = {}
        self.by_name = {}
        nid = 2
        for name, data in files.items():
            self.nodes[nid] = (name, data)
            self.by_name[name] = nid
            nid += 1
        self.receipt = open(receipt_path, "w", buffering=1)
        self.seq = 0
        self.pages_touched = {}
        self.bytes_served = 0

    # -- receipt -------------------------------------------------------------

    def emit(self, nodeid, off, length, data):
        """Record ONE READ the kernel asked for. Called after the slice is chosen."""
        self.seq += 1
        kind = (PAGE_ALIGNED if (off % PAGE == 0 and length == PAGE)
                else OTHER)
        name = self.nodes[nodeid][0]
        # A zero-length read delivered no page. `max(length, 1)` here would make
        # a past-EOF request register page 0 (or the page at its offset) as
        # touched, i.e. "asked and served nothing" would count as a read — the
        # exact conflation this instrument exists to prevent. Caught by control 9.
        if length > 0:
            first = off // PAGE
            last = (off + length - 1) // PAGE
            self.pages_touched.setdefault(name, set()).update(range(first, last + 1))
        self.bytes_served += len(data)
        self.receipt.write(json.dumps({
            "seq": self.seq,
            "nodeid": nodeid,
            "file": name,
            "off": off,
            "len": length,
            "sha256": hashlib.sha256(data).hexdigest(),
            "kind": kind,
        }, sort_keys=True) + "\n")

    def summary(self):
        return {
            "reads": self.seq,
            "bytes_served": self.bytes_served,
            "pages_touched": {k: sorted(v) for k, v in self.pages_touched.items()},
        }

    # -- protocol ------------------------------------------------------------

    def reply(self, fd, unique, body, err=0):
        os.write(fd, OUT_HDR.pack(len(body) + 16, -err if err else 0, unique) + body)

    def serve(self, devfd):
        while True:
            try:
                raw = os.read(devfd, 1 << 20)
                # A read() on /dev/fuse returns ONE request, but the buffer may
                # be shorter than the header's len (observed: a 19-byte READ
                # body where fuse_read_in requires 20). Keep reading until the
                # announced length is complete; treating a fragment as a whole
                # message crashes the daemon on a valid request.
                while len(raw) >= 40:
                    want = IN_HDR.unpack(raw[:40])[0]
                    if len(raw) >= want:
                        raw = raw[:want]
                        break
                    more = os.read(devfd, want - len(raw))
                    if not more:
                        break
                    raw += more
            except OSError as e:
                # ENODEV = unmounted. EINVAL here means the kernel tore the
                # connection down (a malformed reply earlier), which must be
                # reported, never swallowed — a silent exit leaves a mount with
                # no server, and that reads as "the fixture is empty".
                if e.errno == errno.ENODEV:
                    return
                raise
            if not raw:
                return
            if self.serve_one(devfd, raw) == "stop":
                return

    def serve_one(self, devfd, raw):
        """Handle exactly one fuse_in_header + body. Returns "stop" on DESTROY."""
        ln, opcode, unique, nodeid, uid, gid, pid, _pad = IN_HDR.unpack(raw[:40])
        body = raw[40:ln]

        if opcode == FUSE_INIT:
            # fuse_init_out for 7.45 is exactly 64 bytes:
            #   major, minor, max_readahead, flags (16), max_background u16,
            #   congestion u16, max_write u32, time_gran u32, max_pages u16,
            #   map_alignment u16, flags2 u32, max_stack_depth u32,
            #   request_timeout u16, unused[11] u16
            # The 7.31-era layout used here first (max_pages placed two bytes
            # earlier, no max_stack_depth) replies 80 bytes and the kernel tears
            # the connection down: every later read() on /dev/fuse returns
            # EINVAL while the mount stays listed, so the daemon looks dead.
            # Measured 2026-11-04 against a 7.45 kernel.
            self.reply(devfd, unique, struct.pack(
                "<IIIIHHIIHHIIH11H",
                7, 45, 1 << 17, 0, 16, 12, 1 << 17, 1, 256, 0, 0, 0, 0,
                *([0] * 11)))
            return None

        if opcode == FUSE_DESTROY:
            return "stop"

        if opcode in (FUSE_FORGET, FUSE_BATCH_FORGET):
            return None                      # no reply by protocol

        if opcode == FUSE_LOOKUP:
            name = body.split(b"\0", 1)[0].decode()
            if name in self.by_name:
                nid = self.by_name[name]
                data = self.nodes[nid][1]
                self.reply(devfd, unique,
                           ENTRY.pack(nid, 0, 1, 1, 0, 0)
                           + attr_block(nid, len(data), stat.S_IFREG | 0o444))
            elif name in (".", ".."):
                self.reply(devfd, unique,
                           ENTRY.pack(ROOT_NODE, 0, 1, 1, 0, 0)
                           + attr_block(ROOT_NODE, 0, stat.S_IFDIR | 0o555, 2))
            else:
                self.reply(devfd, unique, b"", errno.ENOENT)
            return None

        if opcode in (FUSE_GETATTR, FUSE_SETATTR):
            if nodeid == ROOT_NODE:
                self.reply(devfd, unique,
                           ATTR_OUT.pack(1, 0, 0)
                           + attr_block(ROOT_NODE, 0, stat.S_IFDIR | 0o555, 2))
            elif nodeid in self.nodes:
                data = self.nodes[nodeid][1]
                self.reply(devfd, unique,
                           ATTR_OUT.pack(1, 0, 0)
                           + attr_block(nodeid, len(data), stat.S_IFREG | 0o444))
            else:
                self.reply(devfd, unique, b"", errno.ENOENT)
            return None

        if opcode in (FUSE_OPEN, FUSE_OPENDIR):
            # fh 0, open_flags 0: keep the page cache. mmap needs it, and the
            # receipt's granularity claim depends on the kernel being the reader.
            self.reply(devfd, unique, OPEN_OUT.pack(0, 0, 0))
            return None

        if opcode == FUSE_READ:
            _fh, off, size = struct.unpack("<QQI", body[:20])
            if nodeid not in self.nodes:
                self.reply(devfd, unique, b"", errno.ENOENT)
                return None
            data = self.nodes[nodeid][1]
            if off >= len(data):
                # Past EOF: the kernel asked and no bytes exist. Recorded with
                # len=0 so "asked, served nothing" is not silently dropped.
                self.emit(nodeid, off, 0, b"")
                self.reply(devfd, unique, b"")
                return None
            chunk = data[off:off + size]
            self.emit(nodeid, off, len(chunk), chunk)
            self.reply(devfd, unique, chunk)
            return None

        if opcode == FUSE_READDIR:
            # d_type is a DT_* constant, not an st_mode mask.
            ents = [(ROOT_NODE, ".", 4), (ROOT_NODE, "..", 4)]
            ents += [(nid, name, 8)
                     for nid, (name, _d) in sorted(self.nodes.items())]
            # READDIR is offset-paged and the offset is the caller's cursor:
            # returning the whole listing every time makes the kernel ask
            # forever (observed: 25+ consecutive READDIR, empty directory).
            # `off` is the fuse_read_in.offset; `size` is the reply budget.
            _fh, off, size = struct.unpack("<QQI", body[:20])
            out = b""
            for i, (ino, name, typ) in enumerate(ents):
                if i < off:
                    continue
                nb = name.encode()
                ent = struct.pack("<QQII", ino, i + 1, len(nb), typ) + nb
                ent += b"\0" * (-len(ent) % 8)
                if len(out) + len(ent) > size:
                    break
                out += ent
            self.reply(devfd, unique, out)
            return None

        if opcode in (FUSE_RELEASE, FUSE_RELEASEDIR, FUSE_FLUSH, FUSE_ACCESS):
            self.reply(devfd, unique, b"")
            return None

        if opcode == FUSE_STATFS:
            self.reply(devfd, unique, b"", errno.ENOSYS)
            return None

        if opcode in (FUSE_GETXATTR, FUSE_LISTXATTR):
            self.reply(devfd, unique, b"", errno.ENODATA)
            return None

        self.reply(devfd, unique, b"", errno.ENOSYS)
        return None


# ---------------------------------------------------------------- mounting

def mount_fuse(mnt, opts=""):
    """Mount via setuid fusermount3 and return (kernel_fd, devfd).

    Note: on Ubuntu 24.04+ the AppArmor profile `fusermount3` allows an
    unprivileged FUSE mount only under $HOME, /tmp, /mnt, /media and
    /run/user/<uid>. A mount under /var/tmp fails with EACCES from the mount
    itself even though /var/tmp is world-writable — measured 2026-11-04.
    """
    fd = os.open("/dev/fuse", os.O_RDWR)
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    pid = os.fork()
    if pid == 0:
        try:
            os.close(a.fileno())
            os.close(fd)
            os.set_inheritable(b.fileno(), True)
            base = f"rootmode=40000,user_id={os.getuid()},group_id={os.getgid()}"
            env = {"PATH": "/usr/bin:/bin", "_FUSE_COMMFD": str(b.fileno())}
            os.execve("/usr/bin/fusermount3",
                      ["fusermount3", "-o", base + (("," + opts) if opts else ""),
                       "--", mnt], env)
        except BaseException:
            os._exit(127)
    b.close()
    # The third positional argument of recvmsg is *flags*, not a buffer size —
    # passing 4096 there silently returns no ancillary data and the mount looks
    # refused while it actually succeeded. ancbufsize is what carries the fd.
    msg, ancdata, _flags, _addr = a.recvmsg(64, socket.CMSG_SPACE(4 * 4))
    # ancdata is a list of (cmsg_level, cmsg_type, cmsg_data) — NOT a list of
    # fds. Treating it as fds put a tuple where an int belongs, so every
    # os.write() raised TypeError and the daemon died on the first INIT while
    # the mount itself succeeded: a mount with no server, which reads as
    # "the fixture is empty" rather than "the daemon crashed".
    fds = []
    for level, typ, data in ancdata:
        if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            fds.extend(struct.unpack("<%di" % (len(data) // 4), data))
    _pid, status = os.waitpid(pid, 0)
    a.close()
    if not fds:
        os.close(fd)
        raise RuntimeError(
            "fusermount3 gave no fd (status %d, reply %r) — on AppArmor-confined "
            "hosts the mountpoint must be under $HOME, /tmp, /mnt, /media or "
            "/run/user/<uid>" % (status, msg))
    return fd, fds[0]


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="directory holding the fixture")
    ap.add_argument("--mount", required=True, help="mountpoint (must be AppArmor-allowed)")
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--served", required=True, help="manifest of what was served")
    ap.add_argument("--ready-file", default=None)
    args = ap.parse_args()

    files = {}
    for name in sorted(os.listdir(args.root)):
        p = os.path.join(args.root, name)
        if os.path.isfile(p):
            with open(p, "rb") as fh:
                files[name] = fh.read()
    if not files:
        sys.exit("no fixture files in %s" % args.root)

    fs = ReadSetFS(files, args.receipt)
    os.makedirs(args.mount, exist_ok=True)
    kfd, devfd = mount_fuse(args.mount)

    # content is embedded so a stranger can recompute every per-slice hash in
    # the receipt against the bytes that were served, without trusting this
    # process and without needing the fixture directory to survive the run.
    import base64
    with open(args.served, "w") as fh:
        json.dump({n: {"size": len(d), "sha256": hashlib.sha256(d).hexdigest(),
                       "b64": base64.b64encode(d).decode()}
                   for n, d in files.items()}, fh, indent=1, sort_keys=True)

    if args.ready_file:
        with open(args.ready_file, "w") as fh:
            fh.write("ready %d\n" % os.getpid())

    # SIGTERM is how every case ends. Without a handler the interpreter dies
    # before the `finally`, so receipt.summary is never written and the run
    # reports `reads=0` beside a receipt full of lines — a counter whose write
    # path is not the path the process actually takes.
    import signal
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    try:
        fs.serve(devfd)
    finally:
        summary = fs.summary()
        fs.receipt.close()
        subprocess.run(["/usr/bin/fusermount3", "-u", args.mount],
                       capture_output=True)
        try:
            os.close(devfd)
        except OSError:
            pass
        try:
            os.close(kfd)
        except OSError:
            pass
        with open(args.receipt + ".summary", "w") as fh:
            json.dump(summary, fh, indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
