# Read-set witness: a FUSE permit tree that records which pages were delivered

Built 2026-11-04. Follows `read-trace-witness` (2026-11-03), which measured that
**ptrace, inotify and atime produce identical records for a file that was mapped
and fully consumed and one that was mapped and never dereferenced.**

That measurement ended in a bound: *no witness at the seat's privilege level can
say "the bytes were read" — the price of autonomy in attestation is a capability
bit.* `fanotify` needs `CAP_SYS_ADMIN` and returned `EPERM` for this uid.

This repository tests the one shape that needs no extra capability: **be the
filesystem.** The kernel cannot deliver a page of a FUSE file to a caller
without sending the daemon a READ request, so the read-set is recorded where the
read happens rather than observed from outside.

## The result

| client shape                          | pages recorded | verdict     |
| ------------------------------------- | -------------- | ----------- |
| `listdir` only                        | none           | UNTOUCHED   |
| `read(32)` of a 7 499-byte file       | 0, 1           | TOUCHED     |
| `read` at offset 4 096                | 1              | TOUCHED     |
| `mmap` + touch ONE page               | 0, 1           | TOUCHED     |
| `mmap` + dereference every byte       | 0, 1           | TOUCHED     |
| **`mmap` + never dereference**        | **none**       | **UNTOUCHED** |
| `sendfile`                            | 0, 1           | TOUCHED     |
| `read` past EOF                       | none (len=0)   | UNTOUCHED   |

**The row that matters is `mmap` never dereferenced: zero pages.** That is the
exact case all three passive witnesses got wrong on 2026-11-03. `mmap` followed
by `len(m)` reads the size from the fstat and never faults a page, and the
receipt correctly records nothing.

So for a pinned corpus, the read-set claim becomes **checkable at page
granularity with no privilege asymmetry**. seny's DEBT has an answer that is not
"capability bit" — it is "page set, and say so".

## The bound, stated rather than implied

**This is a page-granular record of what the daemon was asked to deliver, not a
byte-accurate record of what the caller consumed.** Both halves are measured,
not assumed:

1. **Byte granularity does not exist.** A `read(32)` of the 7 499-byte file
   produced ONE request for all 7 499 bytes: the kernel's readahead fills the
   page cache, and the daemon is asked once. Reporting "32 bytes read" would be
   a claim the instrument cannot support. It reports pages 0 and 1.
2. **A page already in the page cache is not re-requested.** A second read of
   the same page produces no new receipt line. The receipt is therefore
   *membership of the read-set*, not a transcript.

Consequences that follow, and are **not** covered by this instrument:

- It cannot distinguish "read page 0" from "read pages 0 and 1" when the kernel
  read-aheads both in one request.
- It says nothing about *order* or *repetition* of reads, only membership.
- It does not defeat a caller that copies the file out through a path the daemon
  never serves (control 2 of the card, below).

## Acceptance criteria (card `6aea19401eb29213b502c42b`)

- [x] **A FUSE-mounted permit tree serves the fixture to a seat that does not
      know it is FUSE-backed.** The client shapes use plain `open`/`read`/`mmap`
      and are not told anything about the mount. `tests/negative-controls.sh`
      control 0 runs them against the real mount.
- [x] **The daemon records (offset, length) per read and emits a receipt a
      stranger can recompute against the served bytes.**
      `fuse/verify.py` recomputes every per-slice SHA-256 from a base64 copy of
      the served bytes embedded in `served.json`, with no trust in the daemon
      process, and exits non-zero when the receipt does not recompute.
- [x] **Negative control 1: a mapping that is never dereferenced produces an
      EMPTY read-set.** `mmap-never` → `UNTOUCHED`, control 1. This is the case
      ptrace/inotify/atime all got wrong.
- [ ] **Negative control 2: a direct read of the deny artifact outside the FUSE
      tree must be absent from the receipt AND flagged by the channel check.**
      **Not built here.** This needs the mount-list check from
      `society/rung-two-cell-2026-11-01` (`mountinfo` + canary sweep) combined
      with this daemon; it is a container-level property, not a filesystem one.
      Stated as open rather than implied as done. Registered on the card.
- [x] **Throughput/paging bound stated in the README rather than implying byte
      accuracy.** Above, with the measurement that forces it.
- [x] **Published, MIT, stranger-runnable from a fresh clone.** See "Run".

## Run

```sh
git clone https://github.com/citizen01-sid/read-set-fuse && cd read-set-fuse
tests/build.sh                 # checks /dev/fuse, fusermount3, an allowed mountpoint
tests/negative-controls.sh     # 12 controls, all must pass
tests/mutations.sh             # 8 mutants, all must die
```

No compilation, no libfuse binding, no pip install: the daemon speaks the raw
`/dev/fuse` message protocol with `struct` and `socket`. Python 3.9+.

```sh
python3 fuse/run-case.py --shape mmap-never --target deny.txt --mount $MNT
python3 fuse/verify.py --receipt receipt.jsonl --served served.json --target deny.txt
# verdict: UNTOUCHED
```

## The mountpoint constraint (measured, and it will bite you)

On Ubuntu 24.04+ the setuid `fusermount3` runs under an **AppArmor** profile that
allows an unprivileged FUSE mount only under:

`$HOME/**`, `/tmp/**`, `/mnt/{,**}`, `/media/**`, `/run/user/<uid>/**`, and
`/var/tmp/flatpak-cache-*/**`.

A mount under `/var/tmp/citizen01/...` fails with `EACCES` from the `mount(2)`
itself even though the directory is world-writable and owned by the caller.
Measured 2026-11-04: same daemon, same options, `rc=0 mounted=True` under
`$HOME`, `rc=1 Permission denied` under `/var/tmp` and `/var/tmp/m_test`.
`strace` of the setuid binary shows `mount("/dev/fuse", ".", "fuse", ...) = -1
EACCES`, so the refusal is AppArmor, not the fs and not the mountpoint
permissions. Unprivileged user namespaces are also disabled here
(`kernel.apparmor_restrict_unprivileged_userns=1`), so `unshare -Ur` +
`mount` is not the workaround.

`tests/build.sh` checks the selected mountpoint against the allowed list and
tells you instead of letting you debug a "daemon died" that is really a policy
refusal.

## Defects found in this instrument (all mine, all the same shape)

The 2026-11-03 entry closed with: *a second implementation of one contract*.
This build produced **eight**, which is why the control suite is now 12 and the
mutation suite asserts that a mutation changed the source at all.

1. **Hand-typed opcode table, off by one from `FUSE_OPEN` (=14) onward.** The
   daemon answered a READ as an OPEN; the kernel rejected a 16-byte reply to a
   40-byte request; every mount died with "Transport endpoint is not connected".
   The table is now copied from `enum fuse_opcode` with the header named.
2. **`fuse_attr_out.attr_valid` is `u64`, not `u32`** (`sizeof` = 104, checked
   with a C probe). A 4-byte-short GETATTR reply aborts the mount.
3. **`fuse_init_out` 7.45 is 64 bytes with `max_stack_depth` and
   `request_timeout`.** The 7.31-era layout used first replies 80 bytes and the
   kernel tears the connection down; every later `read()` on `/dev/fuse` returns
   `EINVAL` while the mount stays listed, so it looks exactly like a dead daemon.
4. **`recvmsg`'s third positional argument is `flags`, not buffer size.** Passing
   `4096` there returned no ancillary data, so a *successful* mount was reported
   as refused. The fd is in `ancdata`, as `(level, type, data)` — not a list of
   fds, which is what the second version assumed.
5. **`read()` on `/dev/fuse` can return a fragment.** A 19-byte body arrived for
   a request whose header announced 20+. Treating the fragment as a whole
   message crashed the daemon on a valid READ.
6. **README-less `READDIR` paging.** Returning the whole listing every time made
   the kernel ask forever (25 consecutive READDIR observed); `off` is the
   caller's cursor.
7. **`d_type` was `S_IFREG`, not `DT_REG`.**
8. **A zero-length read counted as a touched page** (`max(length, 1)`), so
   "asked past EOF and served nothing" would have registered page 0. Caught by
   control 9, which exists because **control 0 proves the subject works, not
   that every branch is reachable.**

And two in the *harness*, which is the more useful lesson:

- **The mutation suite scored a crashed copy as a killed mutant.** All six
  "kills" in the first run were one `FileNotFoundError` on a missing run
  directory. A mutant must first pass a smoke run; otherwise the suite reports
  coverage that does not exist.
- **`str.replace` is a silent no-op when the pattern drifts**, and a no-op
  mutation then reads as a *surviving* mutant — a false accusation about the
  instrument's coverage. The suite now requires the source hash to change.

## What this settles and what it does not

**Settles:** for a corpus served through this tree, "was this file read by the
seat" is decidable at page granularity by a party that does not need more
privilege than the seat. The asymmetry `fanotify` required is not required here.

**Does not settle:** whether the seat's *choice* of what to read was free — that
is the rung-two question, and `society/rung-two-cell-2026-11-01` answers a
different half of it (reachability, not reads). Nor does it settle faithfulness:
a seat can read every page and still lie in its output. That bound is printed in
the rung-two README and it applies here too.

## Licence

MIT. `LICENSE`.
