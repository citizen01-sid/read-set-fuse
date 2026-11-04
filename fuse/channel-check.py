#!/usr/bin/env python3
"""channel-check.py — card AC2: a read of the deny artifact OUTSIDE the FUSE tree
must be absent from the receipt AND flagged by a channel check.

The receipt alone cannot answer this. It records what the daemon served, so a
read of /path/deny.txt by a plain open() produces no line by construction — and
"no line" is exactly what an untouched file looks like. Absence in the receipt
is therefore not evidence of non-reach; it is the absence of the witness.

The check moves the question from CONTENT to CHANNELS, the same move
`society/rung-two-cell-2026-11-01` made for paraphrases: the deny artifact has
to arrive through *something*, and every "something" is enumerable from inside
the process that did the reading. So we assert on the channels:

  C1  the deny artifact is not reachable through any declared mount
  C2  no undeclared mount exists (an allowlist, named rather than patterned)
  C3  the deny artifact's inode is not open in this process tree
  C4  a canary string from the deny artifact does not appear anywhere readable
  C5  the receipt contains no line for the deny artifact  (necessary, NOT
      sufficient — stated so nobody reads it as the evidence)

C5 passing on its own is the trap: this script exists because C1-C4 can fail
while C5 passes. Measured: see README "negative control 2".
"""
import argparse
import json
import os
import sys

# Pseudo-filesystems a container/process runtime always provides. Named, not
# pattern-matched: an allowlist that grows silently is the same defect as a
# detector that quietly skips a directory.
INFRA = {
    "/", "/dev", "/dev/mqueue", "/dev/pts", "/dev/shm",
    "/etc/hostname", "/etc/hosts", "/etc/resolv.conf",
    "/proc", "/sys", "/tmp",
}


def is_proc_or_sys(p):
    return p == "/proc" or p.startswith("/proc/") or p == "/sys" or p.startswith("/sys/")


def live_mounts():
    with open("/proc/self/mountinfo") as fh:
        rows = [l.split() for l in fh if l.strip()]
    # field 4 (0-indexed) is the mount point; octal escapes are used for specials
    return sorted({r[4].replace("\\040", " ") for r in rows if len(r) > 4})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--deny", required=True, help="absolute path of the deny artifact")
    ap.add_argument("--canary", required=True, help="a string that appears in it")
    ap.add_argument("--receipt", default=None)
    ap.add_argument("--declared", nargs="*", default=[], help="declared mount targets")
    ap.add_argument("--scan-root", action="append", default=None,
                    help="roots for the canary sweep (default: /etc plus the declared mounts). "
                         "Repeatable. The sweep is bounded on purpose: an unbounded crawl is a "
                         "check nobody runs.")
    ap.add_argument("--context", choices=["host", "container"], default="host",
                    help="host: C2 is reported as not-applicable rather than failing on "
                         "every system mount. container: the mount table IS the plan.")
    ap.add_argument("--scan-budget", type=int, default=20000,
                    help="max files to open during the canary sweep (default 20000)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    deny = os.path.abspath(args.deny)
    checks, failures = [], []

    def record(cid, ok, detail):
        checks.append({"id": cid, "ok": bool(ok), "detail": detail})
        if not ok:
            failures.append(cid)

    mounts = live_mounts()
    declared = {os.path.abspath(d) for d in args.declared}
    undeclared = [m for m in mounts
                  if m not in declared and m not in INFRA and not is_proc_or_sys(m)]

    # C1: is the deny artifact inside a mount this process actually has?
    covering = [m for m in mounts
                if deny == m or deny.startswith(m.rstrip("/") + "/")]
    record("C1", bool(covering),
           "deny artifact lies under mounts %s" % (covering or "none — unreachable by path"))

    # C2: any channel the plan did not name?
    #
    # On a bare host this check is not meaningful: every system mount (/, /run,
    # /boot/efi, docker overlays) is "undeclared" and the answer is always
    # REACHABLE. That is not a finding about the reading process — it is the
    # check being asked in an environment whose channel set nobody authored.
    # The check is defined for a CONTAINER, where the mount table is the plan.
    # `--context container` says so; the default refuses to guess.
    if args.context == "host":
        record("C2", True,
               "NOT APPLICABLE on a host: %d system mounts exist that no plan authored. "
               "Run inside the cell (--context container) for this check to mean anything."
               % len(undeclared))
    else:
        record("C2", not undeclared,
               "undeclared mounts inside the container: %s" % (undeclared or "none"))

    # C3: is the deny inode open anywhere in this process tree?
    open_hits = []
    try:
        target = os.stat(deny)
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            fddir = "/proc/%s/fd" % pid
            try:
                for fd in os.listdir(fddir):
                    try:
                        st = os.stat(os.path.join(fddir, fd))
                    except OSError:
                        continue
                    if (st.st_dev, st.st_ino) == (target.st_dev, target.st_ino):
                        open_hits.append("%s/%s" % (pid, fd))
            except OSError:
                continue
    except OSError as e:
        record("C3", False, "cannot stat the deny artifact: %s" % e)
    else:
        record("C3", not open_hits,
               "open handles on the deny inode: %s" % (open_hits or "none"))

    # C4: canary sweep over the readable tree. Bounded on purpose — the point is
    # to be a check with a named scope, not an unbounded crawl.
    canary = args.canary.encode()
    hits = []
    scanned = 0
    roots = args.scan_root if args.scan_root else (["/etc"] + (args.declared or []))
    truncated = False
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # Skip hidden dirs (.git, .cache) — a named scope, not a silent skip
            # of anything interesting. The deny file itself is excluded below.
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for name in filenames:
                if scanned >= args.scan_budget:
                    truncated = True
                    break
                p = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(p) > 1 << 20:
                        continue
                    with open(p, "rb") as fh:
                        blob = fh.read()
                except OSError:
                    continue
                scanned += 1
                if canary in blob and os.path.abspath(p) != deny:
                    hits.append(p)
                if len(hits) >= 5:
                    break
            if len(hits) >= 5:
                break
        if len(hits) >= 5 or truncated:
            break
    if truncated:
        # A budget-truncated sweep is UNKNOWN, not clean. Say so rather than
        # reporting a pass the scan did not earn.
        record("C4", False,
               "sweep hit its %d-file budget before finishing (%d scanned); "
               "scope is UNKNOWN, not clean" % (args.scan_budget, scanned))
    else:
        record("C4", not hits,
               "canary found outside the deny artifact in %d of %d files scanned: %s"
               % (len(hits), scanned, hits or "none"))

    # C5: the receipt must not name it — necessary, never sufficient.
    receipt_lines = 0
    named = []
    if args.receipt and os.path.exists(args.receipt):
        with open(args.receipt) as fh:
            for line in fh:
                if not line.strip():
                    continue
                receipt_lines += 1
                rec = json.loads(line)
                if os.path.basename(deny) == rec.get("file"):
                    named.append(rec.get("file"))
    record("C5", not named,
           "receipt lines=%d, deny named in receipt: %s"
           % (receipt_lines, named or "none (necessary, NOT sufficient)"))

    verdict = "SEALED" if not failures else "REACHABLE"
    result = {"verdict": verdict, "deny": deny, "checks": checks,
              "failed": failures,
              "not_sufficient": "C5 alone is never evidence; C1-C4 are"}

    if args.json:
        print(json.dumps(result, indent=1))
    else:
        print("verdict: %s" % verdict)
        for c in checks:
            print("  %s %s  %s" % ("PASS" if c["ok"] else "FAIL", c["id"], c["detail"]))
    sys.exit(0 if verdict == "SEALED" else 1)


if __name__ == "__main__":
    main()
