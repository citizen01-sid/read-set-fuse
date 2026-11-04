#!/usr/bin/env bash
# tests/build.sh — preconditions for an unprivileged FUSE read-set witness.
#
# Everything here is a measured precondition, not a guess: /dev/fuse, a setuid
# fusermount3, and a mountpoint that the host's AppArmor policy actually allows.
set -uo pipefail

ok()  { printf 'OK    %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; FAILED=1; }
FAILED=0

[ -r /dev/fuse ] && [ -w /dev/fuse ] \
  && ok "/dev/fuse is readable and writable" \
  || bad "/dev/fuse is not accessible — this instrument needs it"

[ -x /usr/bin/fusermount3 ] && ok "fusermount3 present" \
  || bad "fusermount3 missing (package fuse3)"

if [ -u /usr/bin/fusermount3 ]; then
  ok "fusermount3 is setuid (required for an unprivileged mount)"
else
  bad "fusermount3 is not setuid — an unprivileged mount will be refused"
fi

if grep -q '^nodev\s*fuse$' /proc/filesystems; then
  ok "kernel has the fuse filesystem"
else
  bad "kernel does not list the fuse filesystem"
fi

MNT="${MNT:-$HOME/fuse-mnt}"
case "$MNT" in
  "$HOME"/*|/tmp/*|/mnt/*|/media/*|/run/user/"$(id -u)"/*|/var/tmp/flatpak-cache-*/*)
    ok "mountpoint $MNT is in the AppArmor-allowed set" ;;
  *)
    bad "mountpoint $MNT is NOT allowed by the host's fusermount3 AppArmor profile.
      Allowed: \$HOME/**, /tmp/**, /mnt/**, /media/**, /run/user/<uid>/**.
      A mount elsewhere fails with EACCES inside mount(2), which is easy to
      misread as 'the daemon died'. Re-run with MNT=\$HOME/fuse-mnt." ;;
esac

if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" = "1" ]; then
  ok "unprivileged userns restricted — expected on Ubuntu 24.04+; the setuid path is what we use"
fi

echo
if [ "$FAILED" -eq 0 ]; then
  echo "build: all preconditions met (no compilation needed; the daemon is pure Python)"
  exit 0
fi
echo "build: preconditions not met — see FAIL lines above"
exit 1
