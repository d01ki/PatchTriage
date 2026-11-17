#!/bin/sh
# Start PatchTriage as the user who owns the mounted project folder.
#
# docker compose starts the CLI services (demo, start, triage, setup) as
# root only for this step. It hands the CLI's own volumes (enrichment cache,
# saved keys) to the owner of ./out or ./ and then drops root for good, so
# on a Linux host the reports in ./out belong to you whatever your uid,
# with no environment variable to set. On Docker Desktop, where mounts
# appear root-owned, and without any mount, the image user (1000) is used.
# The GUI service never starts as root and goes straight to patchtriage.
set -eu

if [ "$(id -u)" != 0 ]; then
  exec patchtriage "$@"
fi

uid=""
gid=""
for dir in /out /work; do
  owner=$(stat -c %u "$dir" 2>/dev/null || echo 0)
  if [ "$owner" != 0 ]; then
    uid=$owner
    gid=$(stat -c %g "$dir")
    break
  fi
done
uid=${uid:-1000}
gid=${gid:-1000}

chown -R "$uid:$gid" /home/patchtriage
export HOME=/home/patchtriage
exec setpriv --reuid="$uid" --regid="$gid" --clear-groups -- patchtriage "$@"
