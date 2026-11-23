#!/usr/bin/env bash
# Creates the test fixtures. Usage: tools/make_fixtures.sh [fixtures_dir]
set -euo pipefail
BASE="${1:-fixtures}"
case "$BASE" in
  fixtures|*/fixtures) ;;
  *) echo "Refusing: directory must be named 'fixtures'" >&2; exit 1 ;;
esac

# Check if running under /mnt/c or other DrvFS mounts
CUR_DIR="$(pwd)"
if [[ "$CUR_DIR" =~ ^/mnt/[a-z] || "$BASE" =~ ^/mnt/[a-z] ]]; then
  echo "WARNING: Running on a Windows mount (/mnt/*). FIFOs and symlinks break or behave differently on DrvFS." >&2
  echo "Please run this project on the native Linux filesystem inside WSL (e.g. ~/SecureFileGuard-Web)." >&2
fi

rm -rf "$BASE"
mkdir -p "$BASE/secure_files/reports" "$BASE/secure_files_backup" "$BASE/outside_dir"

# Inside the jail
echo "public notes"  > "$BASE/secure_files/notes.txt"
echo "marks"         > "$BASE/secure_files/reports/marks.txt"
echo "dots in name"  > "$BASE/secure_files/a..b.txt"

# Outside the jail
echo "OUTSIDE_SECRET" > "$BASE/outside_secret.txt"
echo "OUTSIDE_SECRET" > "$BASE/outside_dir/secret.txt"
echo "sibling private" > "$BASE/secure_files_backup/private.txt"

# Symlinks (relative so the tree can be moved)
ABS="$(cd "$BASE" && pwd)"
cd "$BASE/secure_files"
ln -s notes.txt                 internal_link.txt      # stays inside
ln -s ../outside_secret.txt     link_to_outside_file   # escape: file
ln -s ../outside_dir            link_to_outside_dir    # escape: directory
ln -s chain_b                   chain_a                # chain_a -> chain_b -> outside
ln -s ../outside_secret.txt     chain_b
ln -s /nonexistent_outside_target broken_link          # dangling, points outside
ln -s loop_b loop_a; ln -s loop_a loop_b          # symlink loop
ln -s "$ABS/secure_files/notes.txt" abs_internal_link  # absolute link, stays inside
ln -s reports                   link_to_reports        # directory symlink inside jail
ln -s ../../outside_secret.txt  reports/sub_escape     # symlink in subdir escaping up & out
echo "utf8 content"             > "sécurité_🔒.txt"     # UTF-8 filename inside jail
mkfifo fifo                                       # special file
cd - >/dev/null

echo "Fixtures created in $BASE"
