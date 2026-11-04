#!/usr/bin/env python3
"""verify.py — recompute a read-set receipt from the served bytes alone.

Inputs: the receipt (JSONL of READ requests the daemon answered) and the served
manifest (name -> size, sha256, base64 content). No state from the daemon
process is trusted; the manifest is what the client actually saw.

Prints a verdict and exits non-zero when the receipt does not recompute.

VERDICTS
  TOUCHED    at least one page of the target was requested from the daemon
  UNTOUCHED  the target was opened/listed but no page was ever requested
  UNVERIFIED the receipt does not recompute against the served bytes

The one distinction this instrument exists to make is TOUCHED vs UNTOUCHED for
a mapping. `mmap` without dereferencing must be UNTOUCHED — that is exactly the
case ptrace, inotify and atime all reported identically to a full read.
"""
import argparse
import base64
import hashlib
import json
import sys

PAGE = 4096


def load_manifest(path):
    with open(path) as fh:
        raw = json.load(fh)
    out = {}
    for name, meta in raw.items():
        data = base64.b64decode(meta["b64"])
        digest = hashlib.sha256(data).hexdigest()
        if digest != meta["sha256"]:
            raise SystemExit("manifest self-check failed for %s" % name)
        if len(data) != meta["size"]:
            raise SystemExit("manifest size mismatch for %s" % name)
        out[name] = data
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--served", required=True)
    ap.add_argument("--target", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    files = load_manifest(args.served)

    reads, errors = [], []
    with open(args.receipt) as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                errors.append("line %d is not JSON: %s" % (lineno, e))
                continue
            name = rec.get("file")
            if name not in files:
                errors.append("line %d names unknown file %r" % (lineno, name))
                continue
            data = files[name]
            off, length = rec["off"], rec["len"]
            if off > len(data):
                errors.append("line %d offset %d past EOF %d" % (lineno, off, len(data)))
                continue
            slice_bytes = data[off:off + length]
            got = hashlib.sha256(slice_bytes).hexdigest()
            if got != rec["sha256"]:
                # Distinguish the two ways a FAIL can happen: the daemon served
                # different bytes, or the record was written by a different run.
                errors.append(
                    "line %d: served bytes hash to %s, receipt says %s"
                    % (lineno, got[:12], rec["sha256"][:12]))
                continue
            if len(slice_bytes) != length:
                errors.append("line %d: len %d but slice is %d"
                              % (lineno, length, len(slice_bytes)))
                continue
            reads.append(rec)

    pages = {}
    for rec in reads:
        if rec["len"] == 0:
            continue                      # asked-past-EOF, no page delivered
        first = rec["off"] // PAGE
        last = (rec["off"] + rec["len"] - 1) // PAGE
        pages.setdefault(rec["file"], set()).update(range(first, last + 1))

    target = args.target
    if target is not None:
        touched = sorted(pages.get(target, ()))
        if errors:
            verdict = "UNVERIFIED"
        elif touched:
            verdict = "TOUCHED"
        else:
            verdict = "UNTOUCHED"
    else:
        verdict = "UNVERIFIED" if errors else "TOUCHED"

    result = {
        "verdict": verdict,
        "target": target,
        "pages_touched": {k: sorted(v) for k, v in sorted(pages.items())},
        "reads": len(reads),
        "bytes": sum(r["len"] for r in reads),
        "errors": errors,
    }

    if args.json:
        print(json.dumps(result, indent=1))
    else:
        print("verdict: %s" % verdict)
        if target:
            print("target : %s pages=%s" % (target, sorted(pages.get(target, ())) or "none"))
        for name in sorted(pages):
            if name != target:
                print("other  : %s pages=%s" % (name, sorted(pages[name])))
        print("reads  : %d  bytes: %d" % (len(reads), result["bytes"]))
        for e in errors:
            print("  ERROR %s" % e)

    sys.exit(0 if verdict != "UNVERIFIED" and not errors else 1)


if __name__ == "__main__":
    main()
