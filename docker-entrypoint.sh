#!/bin/sh
# Start PatchTriage as the user who owns the mounted clone.
#
# docker compose starts the CLI services (demo, start, triage, setup) as
# root only for this step. It finds the clone's owner (./ at /work, else
# ./out at /out), gives that user the CLI's own volumes (enrichment cache,
# saved keys) and any root-owned files in ./out left by older versions,
# then drops root for good. So on a Linux host the reports in ./out belong
# to you whatever your uid, with nothing to set.
#
# - Rootless Docker/Podman: container root already is the host user, so
#   it keeps running as root (dropping would lose access to the mounts).
# - Docker Desktop, or no mount: mounts look root-owned; the image user
#   (1000) is used, which Docker Desktop lets write to the mounts.
# - The GUI service never starts as root and goes straight to patchtriage.
set -eu

if [ "$(id -u)" != 0 ]; then
  exec patchtriage "$@"
fi

# In a user namespace, container root maps to an unprivileged host user.
if awk '$1 == 0 && $2 != 0 { found = 1 } END { exit !found }' /proc/self/uid_map
then
  exec patchtriage "$@"
fi

owner_of() { stat -c "$1" "$2" 2>/dev/null || echo 0; }

uid=0
gid=0
for dir in /work /out; do
  if [ "$(owner_of %u "$dir")" != 0 ]; then
    uid=$(owner_of %u "$dir")
    gid=$(owner_of %g "$dir")
    break
  fi
done
if [ "$uid" = 0 ]; then
  uid=1000
  gid=1000
fi

# Only touch what is not already owned by that user.
find /home/patchtriage \( ! -uid "$uid" -o ! -gid "$gid" \) \
  -exec chown -h "$uid:$gid" {} +
if [ -d /out ] && [ "$(owner_of %u /work)" = "$uid" ]; then
  find /out -uid 0 -exec chown -h "$uid:$gid" {} +
fi

export HOME=/home/patchtriage
exec setpriv --reuid="$uid" --regid="$gid" --clear-groups -- patchtriage "$@"
