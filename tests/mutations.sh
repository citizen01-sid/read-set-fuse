#!/usr/bin/env bash
# tests/mutations.sh — every instrument decision must be killable.
#
# For each mutant: break ONE decision in a copy of the source tree, run the
# control suite against that copy, and require it to go red. A mutant that
# survives is either a redundancy (state it) or a decision nothing tests.
#
# Two oracles, deliberately (learned 2026-11-03): an aggregate verdict alone
# cannot see a mutant on a control path a normal run never walks.
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/var/tmp}/readset-mut.XXXXXX")}"
KILLED=0
SURVIVED=0
INVALID=0
STALE=0
SURVIVORS=()
INVALID_NAMES=()
STALE_NAMES=()

mutate() {  # name, python-edit-snippet (applied with the tree as cwd)
  local name="$1"; shift
  rm -rf "$WORK/$name"; mkdir -p "$WORK/$name"
  cp -r "$HERE"/{fuse,fixture,tests} "$WORK/$name"/
  before="$(cat "$WORK/$name/fuse/readset_fuse.py" | sha256sum)"
  ( cd "$WORK/$name" && python3 -c "$1" ) || { echo "SKIP  $name (edit failed)"; return; }
  after="$(cat "$WORK/$name/fuse/readset_fuse.py" | sha256sum)"
  # str.replace() is a no-op when the pattern has drifted from the source, and
  # a no-op mutation then shows up as a SURVIVING mutant — a false accusation
  # about the instrument's test coverage instead of about the harness.
  [ "$before" != "$after" ] || { echo "STALE $name (pattern did not match; mutation not applied)"; return; }
  mkdir -p "$WORK/$name/run"
  # Smoke check FIRST: can this copy mount and serve at all? A copy that cannot
  # run is a broken mutant, not a killed one. Control 0 is the wrong probe for
  # this because mutants that corrupt the receipt are *supposed* to fail it.
  if ! ( cd "$WORK/$name" && python3 fuse/run-case.py --shape read-all --target small.txt \
         --mount "${MNT:-/home/citizen/fuse-mnt}" --cwd "$WORK/$name/run" >/dev/null 2>&1 ); then
    INVALID=$((INVALID+1)); INVALID_NAMES+=("$name")
    echo "BROKEN $name (the mutated copy cannot serve at all — not a kill, a broken edit)"
    return
  fi
  ( cd "$WORK/$name" && WORK="$WORK/$name/run" MNT="${MNT:-/home/citizen/fuse-mnt}" \
    bash tests/negative-controls.sh ) >"$WORK/$name.log" 2>&1
  rc=$?

  if [ $rc -eq 0 ]; then
    SURVIVED=$((SURVIVED+1)); SURVIVORS+=("$name")
    echo "ALIVE $name  (all controls still green — decision untested)"
  else
    KILLED=$((KILLED+1))
    echo "dead  $name  -> $(grep '^FAIL' "$WORK/$name.log" | sed 's/FAIL  control \([0-9]*\).*/\1/' | tr '\n' ',' | sed 's/,$//' | sed 's/^/controls /')"
  fi
}

# 1. The core claim: stop recording page membership. Every case becomes
#    UNTOUCHED, including the one that was read.
mutate "no-page-tracking" '
p="fuse/readset_fuse.py"; s=open(p).read()
s=s.replace("            self.pages_touched.setdefault(name, set()).update(range(first, last + 1))","            pass")
open(p,"w").write(s)'

# 2. Record only the first page of every request. A full read of a 2-page file
#    then claims page 0 alone — the paging bound would silently become a lie.
mutate "first-page-only" '
p="fuse/readset_fuse.py"; s=open(p).read()
s=s.replace("self.pages_touched.setdefault(name, set()).update(range(first, last + 1))",
            "self.pages_touched.setdefault(name, set()).add(first)")
open(p,"w").write(s)'

# 3. Count a READ past EOF as a page. "Asked and served nothing" becomes
#    "touched", which is exactly the broken-session-reads-as-zero failure
#    inverted.
mutate "count-eof-as-touch-v2" '
p="fuse/readset_fuse.py"; s=open(p).read()
s=s.replace("""                self.emit(nodeid, off, 0, b\"\")""",
            """                self.emit(nodeid, off, PAGE, b\"\")""")
open(p,"w").write(s)'

# 4. Stop hashing the served slice. The verifier then cannot recompute against
#    the served bytes, and control 2 should go red — but note this mutant is
#    only visible through the RECEIPT, not through a normal run.
mutate "hash-not-of-slice" '
p="fuse/readset_fuse.py"; s=open(p).read()
s=s.replace("""            chunk = data[off:off + size]
            self.emit(nodeid, off, len(chunk), chunk)""",
            """            chunk = data[off:off + size]
            self.emit(nodeid, off, len(chunk), data[0:len(chunk)])""")
open(p,"w").write(s)'

# 5. Lie about length: report the request size instead of the bytes served.
mutate "len-is-request" '
p="fuse/readset_fuse.py"; s=open(p).read()
s=s.replace("self.emit(nodeid, off, len(chunk), chunk)","self.emit(nodeid, off, size, chunk)")
open(p,"w").write(s)'

# 6. Treat every read as a full page (drop the offset). Offsets stop meaning
#    anything and the receipt is no longer a read-SET.
mutate "offset-dropped" '
p="fuse/readset_fuse.py"; s=open(p).read()
s=s.replace("self.emit(nodeid, off, len(chunk), chunk)","self.emit(nodeid, 0, len(chunk), chunk)")
open(p,"w").write(s)'

# 7. The zero-length guard removed (the defect control 9 just found).
mutate "eof-counts-a-page" '
p="fuse/readset_fuse.py"; s=open(p).read()
s=s.replace("""        if length > 0:
            first = off // PAGE
            last = (off + length - 1) // PAGE
            self.pages_touched.setdefault(name, set()).update(range(first, last + 1))""",
            """        first = off // PAGE
        last = (off + max(length, 1) - 1) // PAGE
        self.pages_touched.setdefault(name, set()).update(range(first, last + 1))""")
open(p,"w").write(s)'

# 8. Emit no receipt line at all but keep the summary — the receipt and the
#    summary are then two sources, and control 8 must notice.
mutate "no-receipt-lines" '
p="fuse/readset_fuse.py"; s=open(p).read()
s=s.replace("""        self.receipt.write(json.dumps({""", """        if False: self.receipt.write(json.dumps({""")
open(p,"w").write(s)'

echo
echo "mutants: $KILLED killed, $SURVIVED survived, $INVALID broken, $STALE stale"
[ ${#SURVIVORS[@]} -gt 0 ] && printf 'survivors: %s\n' "${SURVIVORS[*]}"
[ ${#INVALID_NAMES[@]} -gt 0 ] && printf 'broken: %s\n' "${INVALID_NAMES[*]}"
[ ${#STALE_NAMES[@]} -gt 0 ] && printf 'stale: %s\n' "${STALE_NAMES[*]}"
[ "$SURVIVED" -eq 0 ] && [ "$INVALID" -eq 0 ] && [ "$STALE" -eq 0 ] || exit 1
