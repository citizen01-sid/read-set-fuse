#!/usr/bin/env python3
"""run-case.py — one measured case: start the permit-tree daemon, run ONE client
shape against it, stop it, print the receipt.

Every case is run in its own process pair so a crashed daemon can never be
mistaken for an empty fixture (the 2026-11-03 sendfile defect, one layer up).

Client shapes:
  none        — stat + listdir only, no file content requested
  read-all    — open + read(2) the whole file
  read-part   — open + read(2) only the first N bytes
  cat-file    — `cat` the file (page cache path, short reads)
  mmap-touch  — open + mmap + touch ONE page
  mmap-full   — open + mmap + dereference every byte
  mmap-never  — open + mmap + return WITHOUT dereferencing anything
  read-mid    — open + seek + read from a NON-ZERO offset (tests that the
                recorded offset is the caller's offset, not 0)
  read-past   — open + read from past EOF (tests that "asked and served
                nothing" is recorded as len=0 and is NOT a page)
  sendfile    — open + sendfile to a temp fd
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import readset_fuse as R

CLIENT = r'''
import mmap, os, sys
shape, path = sys.argv[1], sys.argv[2]
out = {}
if shape == "none":
    out["entries"] = len(os.listdir(os.path.dirname(path)))
elif shape == "read-all":
    with open(path, "rb") as f:
        out["bytes"] = len(f.read())
elif shape == "read-part":
    with open(path, "rb") as f:
        out["bytes"] = len(f.read(32))
elif shape == "mmap-touch":
    f = open(path, "rb"); m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
    out["byte0"] = m[0]; m.close(); f.close()
elif shape == "mmap-full":
    f = open(path, "rb"); m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
    n = sum(1 for b in m); out["bytes"] = n; m.close(); f.close()
elif shape == "mmap-never":
    f = open(path, "rb"); m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
    out["mapped"] = len(m)     # len() is from the fstat, not a page fault
    m.close(); f.close()       # closed without ever dereferencing a page
elif shape == "read-mid":
    with open(path, "rb") as f:
        f.seek(4096)
        out["bytes"] = len(f.read(64))
elif shape == "read-past":
    with open(path, "rb") as f:
        f.seek(65536)
        out["bytes"] = len(f.read(64))
elif shape == "sendfile":
    src = os.open(path, os.O_RDONLY)
    # Destination is OUTSIDE the mount: the permit tree is read-only by design,
    # so opening the sink next to the source fails with EROFS and the case
    # silently becomes "sendfile refused" instead of "sendfile measured".
    sink = os.environ["SINK"]
    dst = os.open(sink, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o644)
    n = os.sendfile(dst, src, 0, 65536); out["bytes"] = n
    os.close(src); os.close(dst); os.unlink(sink)
else:
    sys.exit("unknown shape " + shape)
import json as J; print(J.dumps(out))
'''


def run_case(shape, target, mount, daemon, cwd, extra_reads=1):
    for p in (daemon.receipt, daemon.receipt + ".summary", daemon.ready):
        if os.path.exists(p):
            os.unlink(p)
    subprocess.run(["/usr/bin/fusermount3", "-u", mount], capture_output=True)
    time.sleep(0.05)

    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "readset_fuse.py"),
         "--root", os.path.join(os.path.dirname(HERE), "fixture"), "--mount", mount,
         "--receipt", daemon.receipt, "--served", daemon.served,
         "--ready-file", daemon.ready],
        cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    ready = False
    for _ in range(100):
        if os.path.exists(daemon.ready):
            ready = True
            break
        if proc.poll() is not None:
            break
        time.sleep(0.05)
    if not ready:
        log = proc.communicate()[0].decode()
        raise SystemExit("daemon did not become ready: " + log[-800:])

    results = []
    try:
        for _ in range(extra_reads):
            if shape == "cat-file":
                cp = subprocess.run(
                    ["python3", "-c",
                     "import sys;print(sum(1 for b in open(sys.argv[1],'rb')))",
                     os.path.join(mount, target)],
                    capture_output=True, text=True)
            else:
                cp = subprocess.run(
                    [sys.executable, "-c", CLIENT, shape, os.path.join(mount, target)],
                    capture_output=True, text=True,
                    env=dict(os.environ, SINK=os.path.join(cwd, "sendfile.out")))
            results.append({"rc": cp.returncode,
                            "out": cp.stdout.strip(),
                            "err": cp.stderr.strip()[-300:]})
            # let the daemon write its receipt line before the next read/unmount
            time.sleep(0.15)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        subprocess.run(["/usr/bin/fusermount3", "-u", mount], capture_output=True)

    lines = []
    if os.path.exists(daemon.receipt):
        with open(daemon.receipt) as fh:
            lines = [json.loads(l) for l in fh if l.strip()]
    summary = {}
    if os.path.exists(daemon.receipt + ".summary"):
        with open(daemon.receipt + ".summary") as fh:
            summary = json.load(fh)
    return {"shape": shape, "target": target, "client": results,
            "reads": lines, "summary": summary}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shape", required=True)
    ap.add_argument("--target", default="deny.txt")
    ap.add_argument("--mount", required=True)
    ap.add_argument("--cwd", default=os.path.dirname(HERE))
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    class D:
        pass
    d = D()
    d.receipt = os.path.join(args.cwd, "receipt.jsonl")
    d.served = os.path.join(args.cwd, "served.json")
    d.ready = os.path.join(args.cwd, "ready.txt")

    res = run_case(args.shape, args.target, args.mount, d, args.cwd, args.repeat)
    if args.json:
        print(json.dumps(res, indent=1))
    else:
        pages = res["summary"].get("pages_touched", {})
        print("shape=%s target=%s reads=%d bytes=%d pages=%s"
              % (res["shape"], res["target"],
                 res["summary"].get("reads", 0),
                 res["summary"].get("bytes_served", 0), pages or "{}"))
        for r in res["reads"]:
            print("   %s off=%d len=%d %s" % (r["file"], r["off"], r["len"], r["kind"]))
        for c in res["client"]:
            print("   client rc=%d out=%s %s" % (c["rc"], c["out"], c["err"]))


if __name__ == "__main__":
    main()
