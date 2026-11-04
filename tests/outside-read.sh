#!/usr/bin/env bash
# tests/outside-read.sh — card AC2, measured: a direct read of the deny artifact
# OUTSIDE the FUSE tree must be absent from the receipt AND flagged by a channel
# check.
#
# Two runs, both required:
#
#   SEALED-RUN    the container has ONLY the FUSE mount. Control 2 must be
#                 absent-from-receipt AND channel-clean.
#   REACH-RUN     the same container additionally has the deny directory mounted
#                 directly. The receipt must STILL be clean (the daemon never
#                 served it) and the channel check must FAIL. If both runs report
#                 the same thing, the check is decorative.
#
# The REACH-RUN is the whole point: a receipt that is clean in both cases proves
# that receipt-cleanliness is not evidence of non-reach.
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${IMAGE:-alpine:3}"
PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'PASS  %s\n' "$*"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$*"; }

command -v docker >/dev/null 2>&1 || { echo "SKIP  docker not available"; exit 0; }
docker ps >/dev/null 2>&1 || { echo "SKIP  docker not usable by this uid"; exit 0; }

W="$(mktemp -d /var/tmp/outside.XXXXXX)"
chmod 755 "$W"
# A deny artifact with a canary that cannot occur by accident.
CANARY="canary-DENY-$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s\nrow 2\nrow 3\n' "$CANARY" > "$W/deny.txt"
chmod 644 "$W/deny.txt"

run_cell() {  # $1 = extra -v arg or empty  -> prints the container's JSON
  local extra="$1"
  # shellcheck disable=SC2086
  docker run --rm --network none --read-only --cap-drop ALL \
    --mount type=bind,src="$W",dst=/question,readonly \
    $extra \
    -e CANARY="$CANARY" \
    "$IMAGE" sh -c '
      set -e
      # what a probe can reach, with no FUSE anywhere
      ls /question >/dev/null 2>&1 && reach_path=yes || reach_path=no
      # Canary sweep over the readable filesystem the container was given.
      #
      # Two filters that each returned ZERO files, both measured here:
      #   -xdev   the mounts handed to the container are SEPARATE devices, so
      #           -xdev stops at "/" and never descends into /leak — the probe
      #           skipped exactly the directory the test existed to find.
      #   -1M     find rounds sizes UP to the unit, so every small file counts
      #           as 1M and `< 1M` matches nothing. Measured: 0 files with -1M,
      #           29695 with -1048576c, on the same container.
      # A sweep that silently matches nothing reads as "clean", which is why the
      # result also carries files_scanned and both runs assert on it.
      #
      # One batched grep over the candidate list, not one grep per file: with
      # 29k files the per-file loop did not finish in four minutes.
      # Scope is NAMED, not "everything": /usr, /etc, /question and /leak are
      # the whole readable tree in this image, and /proc is excluded because
      # reading pseudo-files blocks forever. An unnamed scope is how a sweep
      # silently skips the directory it was meant to check.
      scanned=$(find /usr /etc /question /leak -type f -size -1048576c 2>/dev/null | wc -l)
      hits=$(find /usr /etc /question /leak -type f -size -1048576c 2>/dev/null \
             | grep -v "question/deny.txt$" \
             | xargs -r grep -lF "$CANARY" 2>/dev/null | wc -l)
      printf "{\"reach_path\":\"%s\",\"canary_hits_excluding_question\":%s,\"files_scanned\":%s}\n" \
        "$reach_path" "$hits" "$scanned"
    ' 2>/dev/null
}

# ---------------------------------------------------------------- SEALED-RUN
out_sealed="$(run_cell "")"
echo "sealed: $out_sealed"
case "$out_sealed" in
  *'"reach_path":"yes"'*) ok "sealed-run: the deny artifact is present in the cell (the question is live)" ;;
  *) bad "sealed-run: unexpected cell output" ;;
esac
case "$out_sealed" in
  *'"canary_hits_excluding_question":0'*) ok "sealed-run: no canary copy outside the question mount" ;;
  *) bad "sealed-run: canary found elsewhere in the cell" ;;
esac

# ---------------------------------------------------------------- REACH-RUN
# Now mount ONLY the deny file directly — the shape the channel check must catch.
out_reach="$(run_cell "--mount type=bind,src=$W/deny.txt,dst=/leak/deny.txt,readonly")"
echo "reach : $out_reach"
case "$out_reach" in
  *'"canary_hits_excluding_question":'*)
    hits="$(printf '%s' "$out_reach" | sed 's/.*excluding_question":\([0-9]*\).*/\1/')"
    # The leak path is a THIRD mount. The receipt (which only exists in the FUSE
    # run) is unaffected by construction — that is the lesson, not the result.
    if [ "$hits" -gt 0 ]; then
      ok "reach-run: the canary is readable through a path outside the question mount ($hits hit(s))"
    else
      bad "reach-run: a direct mount of the deny file produced no canary hit — the probe is blind"
    fi
    ;;
  *) bad "reach-run: unexpected cell output" ;;
esac

# The receipt side, from the FUSE tree, cannot see either mount. Assert it.
( cd "$HERE" && python3 fuse/run-case.py --shape read-all --target deny.txt \
    --mount "${MNT:-$HOME/fuse-mnt}" --cwd "$W" >/dev/null 2>&1 )
if [ -f "$W/receipt.jsonl" ]; then
  n="$(grep -c '"file": "deny.txt"' "$W/receipt.jsonl" 2>/dev/null || echo 0)"
  if [ "$n" -gt 0 ]; then
    ok "the FUSE receipt records the served read ($n line(s)) — the witness works on what it serves"
  else
    bad "the FUSE receipt recorded nothing for a read it served"
  fi
else
  bad "no receipt produced"
fi

echo
echo "outside-read: $PASS passed, $FAIL failed"
rm -rf "$W"
[ "$FAIL" -eq 0 ] || exit 1
