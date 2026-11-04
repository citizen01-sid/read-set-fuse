#!/usr/bin/env bash
# tests/negative-controls.sh — every detector must be shown to refuse.
#
# The rule this file enforces (learned 2026-11-03, five defects in one
# instrument): BEFORE adding controls for an instrument's DECISIONS, add one
# that its SUBJECT succeeds at all. A control that cannot fail proves nothing.
#
#  0  subject succeeds: mmap-touch is TOUCHED and its receipt recomputes clean
#  1  the 2026-11-03 gap: mmap-never is UNTOUCHED
#  2  a tampered slice hash is refused (UNVERIFIED, non-zero exit)
#  3  a receipt line naming an unserved file is refused
#  4  a flipped byte in the served manifest is caught at load
#  5  the documented bound: an empty receipt still reads UNTOUCHED
#  6  a read at a non-zero offset records THAT page, not page 0
#  7  a full read of a 2-page file records BOTH pages
#  8  the daemon's own summary and the verifier agree on the page set
#     (two implementations of one contract — the defect shape of this week)
#  9  a zero-length read records no page (unit on the decision itself)
#
# Control 5 is deliberately a PASS on the weak behaviour: it pins the bound so
# nobody later mistakes an empty receipt for evidence of non-reading.
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
MNT="${MNT:-/home/citizen/fuse-mnt}"
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/var/tmp}/readset.XXXXXX")}"
PASS=0
FAIL=0

say() { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "PASS  $*"; }
bad()  { FAIL=$((FAIL+1)); say "FAIL  $*"; }

mkdir -p "$MNT" 2>/dev/null || true
mkdir -p "$WORK"

case_run() {
  ( cd "$HERE" && python3 fuse/run-case.py --shape "$1" --target "$2" --mount "$MNT" \
      --cwd "$WORK" >/dev/null 2>&1 )
}
verify() {  # target -> json
  ( cd "$HERE" && python3 fuse/verify.py --receipt "$WORK/receipt.jsonl" \
      --served "$WORK/served.json" --target "$1" --json 2>/dev/null )
}
verdict() { verify "$1" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("verdict","NOJSON"))'; }
pages()   { verify "$1" | python3 -c 'import json,sys
d=json.load(sys.stdin); print(",".join(str(p) for p in d["pages_touched"].get(sys.argv[1],[])))' "$1"; }

# ---------------------------------------------------------------- control 0
case_run mmap-touch small.txt
v="$(verdict small.txt)"
errs="$(verify small.txt | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["errors"]))')"
( cd "$HERE" && python3 fuse/verify.py --receipt "$WORK/receipt.jsonl" \
    --served "$WORK/served.json" --target small.txt >/dev/null 2>&1 )
rc=$?
[ "$v" = "TOUCHED" ] && [ "$errs" = "0" ] && [ $rc -eq 0 ] \
  && ok "control 0: the subject succeeds (mmap-touch TOUCHED, receipt recomputes, exit 0)" \
  || bad "control 0: mmap-touch verdict=$v errors=$errs exit=$rc — instrument broken, not a result"

# ---------------------------------------------------------------- control 1
case_run mmap-never small.txt
v="$(verdict small.txt)"
[ "$v" = "UNTOUCHED" ] && ok "control 1: a mapping never dereferenced is UNTOUCHED" \
                       || bad "control 1: mmap-never gave $v, expected UNTOUCHED"

# ---------------------------------------------------------------- control 2
case_run mmap-touch small.txt
python3 - "$WORK/receipt.jsonl" <<'PY'
import json, sys
p = sys.argv[1]
lines = [json.loads(l) for l in open(p) if l.strip()]
assert lines, "no receipt lines to tamper with"
lines[0]["sha256"] = "0" * 64
open(p, "w").write("".join(json.dumps(l) + "\n" for l in lines))
PY
( cd "$HERE" && python3 fuse/verify.py --receipt "$WORK/receipt.jsonl" \
    --served "$WORK/served.json" --target small.txt >/dev/null 2>&1 )
rc=$?
v="$(verdict small.txt)"
[ $rc -ne 0 ] && [ "$v" = "UNVERIFIED" ] \
  && ok "control 2: a receipt whose slice hash does not recompute is refused" \
  || bad "control 2: tampered hash gave verdict=$v exit=$rc, expected UNVERIFIED/non-zero"

# ---------------------------------------------------------------- control 3
case_run mmap-touch small.txt
python3 - "$WORK/receipt.jsonl" <<'PY'
import json, sys
p = sys.argv[1]
lines = [json.loads(l) for l in open(p) if l.strip()]
lines.append({"seq": 999, "nodeid": 9, "file": "not-served.txt",
              "off": 0, "len": 4, "sha256": "a" * 64, "kind": "read-fill"})
open(p, "w").write("".join(json.dumps(l) + "\n" for l in lines))
PY
( cd "$HERE" && python3 fuse/verify.py --receipt "$WORK/receipt.jsonl" \
    --served "$WORK/served.json" --target small.txt >/dev/null 2>&1 )
rc=$?
[ $rc -ne 0 ] && ok "control 3: a receipt naming a file that was not served is refused" \
              || bad "control 3: fabricated file entry was accepted (exit $rc)"

# ---------------------------------------------------------------- control 4
case_run mmap-touch small.txt
python3 - "$WORK/served.json" "$WORK/served.bad.json" <<'PY'
import base64, json, sys
src, dst = sys.argv[1], sys.argv[2]
m = json.load(open(src))
d = bytearray(base64.b64decode(m["small.txt"]["b64"]))
d[0] ^= 0xFF
m["small.txt"]["b64"] = base64.b64encode(bytes(d)).decode()
json.dump(m, open(dst, "w"))
PY
( cd "$HERE" && python3 fuse/verify.py --receipt "$WORK/receipt.jsonl" \
    --served "$WORK/served.bad.json" --target small.txt >/dev/null 2>&1 )
rc=$?
[ $rc -ne 0 ] && ok "control 4: a flipped byte in the served manifest is caught at load" \
              || bad "control 4: a corrupted manifest was accepted (exit $rc)"

# ---------------------------------------------------------------- control 5
case_run mmap-touch small.txt
: > "$WORK/receipt.jsonl"
out="$( cd "$HERE" && python3 fuse/verify.py --receipt "$WORK/receipt.jsonl" \
    --served "$WORK/served.json" --target small.txt 2>&1 )"
if printf '%s' "$out" | grep -q "verdict: UNTOUCHED"; then
  ok "control 5: an empty receipt still reads UNTOUCHED — bound is documented, not hidden"
else
  bad "control 5: expected the documented UNTOUCHED-on-empty bound, got: $out"
fi

# ---------------------------------------------------------------- control 6
case_run read-mid deny.txt
p="$(pages deny.txt)"
[ "$p" = "1" ] && ok "control 6: a read at offset 4096 records page 1, not page 0" \
               || bad "control 6: read-mid recorded pages [$p], expected [1]"

# ---------------------------------------------------------------- control 7
case_run read-all deny.txt
p="$(pages deny.txt)"
[ "$p" = "0,1" ] && ok "control 7: a full read of the 2-page file records BOTH pages" \
                 || bad "control 7: read-all recorded pages [$p], expected [0,1]"

# ---------------------------------------------------------------- control 8
case_run read-all deny.txt
python3 - "$WORK/receipt.jsonl.summary" "$WORK/receipt.jsonl" "$WORK/served.json" <<'PY'
import base64, hashlib, json, sys
summary = json.load(open(sys.argv[1]))
PAGE = 4096
files = {n: base64.b64decode(m["b64"]) for n, m in json.load(open(sys.argv[3])).items()}
recomputed = {}
for line in open(sys.argv[2]):
    if not line.strip():
        continue
    r = json.loads(line)
    if r["len"] == 0:
        continue
    recomputed.setdefault(r["file"], set()).update(
        range(r["off"] // PAGE, (r["off"] + r["len"] - 1) // PAGE + 1))
recomputed = {k: sorted(v) for k, v in recomputed.items()}
daemon = {k: sorted(v) for k, v in summary["pages_touched"].items()}
if daemon != recomputed:
    print("MISMATCH daemon=%s recomputed=%s" % (daemon, recomputed))
    sys.exit(1)
PY
[ $? -eq 0 ] && ok "control 8: the daemon's own summary equals the verifier's page set" \
             || bad "control 8: daemon summary and receipt disagree (two implementations)"

# ---------------------------------------------------------------- control 9
# Unit control on the decision itself: a zero-length (past-EOF) read must not
# contribute a page. The kernel does not send that request on this kernel, so
# only a direct call can reach the branch — and a branch nothing reaches is how
# 2026-11-03's sendfile defect shipped.
#
# NOTE: this control calls emit() directly, so it does NOT see a mutation at the
# CALL SITE (e.g. passing `size` instead of len(chunk) at the past-EOF branch).
# Mutants that only move the call site are covered by control 8 instead, because
# they change what the receipt says relative to the summary.
( cd "$HERE" && python3 - <<'PY'
import os, sys, tempfile
sys.path.insert(0, "fuse")
import readset_fuse as R
fd, path = tempfile.mkstemp()
os.close(fd)
fs = R.ReadSetFS({"x.txt": b"abc"}, path)
fs.emit(2, 0, 0, b"")          # asked past EOF, nothing served
bad = fs.summary()["pages_touched"]
os.unlink(path)
sys.exit(1 if bad else 0)
PY
)
[ $? -eq 0 ] && ok "control 9: a zero-length read contributes no page" \
             || bad "control 9: a zero-length read was counted as a touched page"

[ "$FAIL" -eq 0 ] || exit 1

# --------------------------------------------------------------- control 10
# The call-site control control 9 cannot be: drive a REAL request through the
# daemon and require that a 1-byte read of a 1-page file touches exactly page 0.
# Control 9 calls emit() directly and therefore cannot see a mutation at the
# call site; this one runs the whole path.
MNT="$MNT" python3 - <<'PY'
import json, os, subprocess, sys, tempfile, time
sys.path.insert(0, "fuse")

MNT = os.environ.get("MNT", "/home/citizen/fuse-mnt")
tmp = tempfile.mkdtemp()
receipt = os.path.join(tmp, "r.jsonl")
served = os.path.join(tmp, "s.json")
ready = os.path.join(tmp, "ready")
subprocess.run(["/usr/bin/fusermount3", "-u", MNT], capture_output=True)

proc = subprocess.Popen(
    [sys.executable, "fuse/readset_fuse.py", "--root", "fixture", "--mount", MNT,
     "--receipt", receipt, "--served", served, "--ready-file", ready],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(80):
    if os.path.exists(ready):
        break
    time.sleep(0.05)
else:
    print("daemon never became ready"); sys.exit(1)

try:
    fd = os.open(os.path.join(MNT, "small.txt"), os.O_RDONLY)
    os.read(fd, 1)              # one byte: page 0 only
    os.close(fd)
    time.sleep(0.25)
finally:
    proc.terminate()
    proc.wait(timeout=5)
    subprocess.run(["/usr/bin/fusermount3", "-u", MNT], capture_output=True)

pages = json.load(open(receipt + ".summary"))["pages_touched"].get("small.txt", [])
lines = [json.loads(l) for l in open(receipt) if l.strip()]
if not lines:
    print("no receipt lines: the daemon recorded nothing"); sys.exit(1)
if pages != [0]:
    print("expected pages [0] from a 1-byte read, got %s" % pages); sys.exit(1)
sys.exit(0)
PY
[ $? -eq 0 ] && ok "control 10: a 1-byte read touches exactly page 0 (full daemon path)" \
             || bad "control 10: full-path page accounting is wrong"

[ "$FAIL" -eq 0 ] || exit 1

# --------------------------------------------------------------- control 11
# The past-EOF branch of serve_one, reached the only way it can be reached on
# this kernel: a synthetic READ message. The kernel never sends one (it knows
# i_size), so without this control the mutation that turns "served nothing" into
# "touched a page" survives every real run — a decision nothing tests.
python3 - <<'PY'
import json, os, socket, struct, sys, tempfile
sys.path.insert(0, "fuse")
import readset_fuse as R

tmp = tempfile.mkdtemp()
path = os.path.join(tmp, "r.jsonl")
fs = R.ReadSetFS({"small.txt": b"abc"}, path)
srv, cli = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

# synthetic READ, nodeid 2 (small.txt), offset far past EOF
body = struct.pack("<QQIIQ", 0, 65536, 4096, 0, 0)
msg = R.IN_HDR.pack(40 + len(body), R.FUSE_READ, 7, 2, 0, 0, 0, 0) + body
fs.serve_one(srv.fileno(), msg)

summary = fs.summary()
pages = summary["pages_touched"].get("small.txt", [])
lines = [json.loads(l) for l in open(path) if l.strip()]
fs.receipt.close()
os.unlink(path)

if pages:
    print("past-EOF READ recorded pages %s — it delivered no bytes" % pages); sys.exit(1)
if not lines:
    print("past-EOF READ was not recorded at all"); sys.exit(1)
if lines[-1]["len"] != 0:
    print("past-EOF READ recorded len=%s, expected 0 (request size 4096)"
          % lines[-1]["len"]); sys.exit(1)
sys.exit(0)
PY
[ $? -eq 0 ] && ok "control 11: a past-EOF READ is recorded with len=0 and touches no page" \
             || bad "control 11: past-EOF accounting is wrong at the call site"

# --------------------------------------------------------------- control 12
# AC2 in one line: the channel check must be able to DISAGREE. Run it against a
# receipt for a served read (clean) and against a deliberately leaked copy of the
# deny artifact (dirty). If both come back the same, it is decorative.
LEAK="$(mktemp -d /var/tmp/leak.XXXXXX)"
CANARY="canary-DENY-unit-$$"
printf '%s\n' "$CANARY" > "$LEAK/deny.txt"
printf '%s\n' "$CANARY" > "$LEAK/copy-of-deny.txt"
python3 fuse/channel-check.py --deny "$LEAK/deny.txt" --canary "$CANARY" \
  --scan-root "$LEAK" --scan-budget 1000 >/dev/null 2>&1
rc=$?
[ $rc -ne 0 ] && ok "control 12: the channel check calls a leaked copy REACHABLE" \
              || bad "control 12: a copy of the deny artifact beside it was called SEALED"
rm -f "$LEAK/copy-of-deny.txt"
python3 fuse/channel-check.py --deny "$LEAK/deny.txt" --canary "$CANARY" \
  --scan-root "$LEAK" --scan-budget 1000 >/dev/null 2>&1
rc=$?
[ $rc -eq 0 ] && ok "control 12b: the same check calls the artifact alone SEALED" \
              || bad "control 12b: a clean tree was called REACHABLE (check is stuck on)"
rm -rf "$LEAK"

say ""
say "controls: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
