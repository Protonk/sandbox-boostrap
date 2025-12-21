#!/bin/sh

# Demonstrates SBPL metafilters (`require-any/all/not`) using sandbox-exec.
# Each profile is tiny and focused on file-read*, so you can match the boolean
# structure to the graph patterns described in book/substrate/Appendix.md (metafilters
# disappear in the compiled graph but their logic remains).

if ! command -v sandbox-exec >/dev/null 2>&1; then
  echo "sandbox-exec not available on this system; showing profile contents only."
  exit 0
fi

TMPDIR=$(mktemp -d /tmp/metafilter-demo.XXXXXX)
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

# Prepare test files.
echo "allowed content" > /tmp/metafilter_any_ok
echo "blocked content" > /tmp/metafilter_any_block_me
echo "blocked too" > /tmp/metafilter_any_also_block

mkdir -p /tmp/metafilter_all
echo "real file" > /tmp/metafilter_all/real.txt
ln -sf /tmp/metafilter_all/real.txt /tmp/metafilter_all/link.txt

mkdir -p /tmp/metafilter_not
echo "plain file" > /tmp/metafilter_not/plain.txt
ln -sf /tmp/metafilter_not/plain.txt /tmp/metafilter_not/symlink.txt

# Profiles: default allow keeps the harness runnable while targeted denies show
# the effect of each metafilter.
PROFILE_ANY="$TMPDIR/require-any.sb"
cat > "$PROFILE_ANY" <<'EOF'
(version 1)
(allow default)
;; Deny reads to two literals if either matches (logical OR).
(deny file-read*
  (require-any
    (literal "/tmp/metafilter_any_block_me")
    (literal "/tmp/metafilter_any_also_block")))
EOF

PROFILE_ALL="$TMPDIR/require-all.sb"
cat > "$PROFILE_ALL" <<'EOF'
(version 1)
(allow default)
;; Deny reads when BOTH the path is under /tmp/metafilter_all AND it is a symlink.
(deny file-read*
  (require-all
    (subpath "/tmp/metafilter_all")
    (vnode-type SYMLINK)))
EOF

PROFILE_NOT="$TMPDIR/require-not.sb"
cat > "$PROFILE_NOT" <<'EOF'
(version 1)
(allow default)
;; Deny reads for non-regular files under /tmp/metafilter_not (NOT regular-file).
(deny file-read*
  (require-all
    (subpath "/tmp/metafilter_not")
    (require-not (vnode-type REGULAR-FILE))))
EOF

run_case() {
  profile=$1
  label=$2
  target=$3
  expected=$4

  sandbox-exec -f "$profile" -- /bin/cat "$target" >/dev/null 2>&1
  rc=$?
  printf "[%s] cat %s -> exit %d (expected %s)\n" "$label" "$target" "$rc" "$expected"
}

echo "Testing require-any (OR)"
run_case "$PROFILE_ANY" "require-any" "/tmp/metafilter_any_ok" "allow"
run_case "$PROFILE_ANY" "require-any" "/tmp/metafilter_any_block_me" "deny"

echo "\nTesting require-all (AND)"
run_case "$PROFILE_ALL" "require-all" "/tmp/metafilter_all/real.txt" "allow"
run_case "$PROFILE_ALL" "require-all" "/tmp/metafilter_all/link.txt" "deny"

echo "\nTesting require-not (NOT)"
run_case "$PROFILE_NOT" "require-not" "/tmp/metafilter_not/plain.txt" "allow"
run_case "$PROFILE_NOT" "require-not" "/tmp/metafilter_not/symlink.txt" "deny"

echo "
Metafilter takeaway:
- require-any: matching any child filter triggers the branch (OR).
- require-all: every child must match to hit the deny branch (AND).
- require-not: flips the sense of the nested filter; in compiled graphs this is
  just control-flow structure, not an explicit NOT opcode (see book/substrate/Appendix.md).
"
