#!/bin/sh

# Demonstrates SBPL parameters via (param "..."). Parameters are evaluated at
# compile/evaluation time and let one profile specialize behavior without
# changing the text (see book/substrate/Appendix.md and Policy Stacking notes).

PROFILE=$(mktemp /tmp/params-demo.XXXXXX.sb)
TARGET_DIR="/tmp/params-allowed"
TARGET_FILE="$TARGET_DIR/from_param.txt"
mkdir -p "$TARGET_DIR"
cleanup() { rm -f "$PROFILE"; }
trap cleanup EXIT

cat > "$PROFILE" <<'EOF'
(version 1)
(allow default)
;; Parameters appear as predicates in the graph; here they gate write access
;; to a single directory. Without ALLOW_DOWNLOADS, writes are denied.
(deny file-write* (subpath "/tmp/params-allowed"))
(allow file-write*
  (require-all
    (param "ALLOW_DOWNLOADS")
    (subpath "/tmp/params-allowed")))
EOF

if ! command -v sandbox-exec >/dev/null 2>&1; then
  echo "sandbox-exec not available; showing the parameterized profile instead:"
  cat "$PROFILE"
  exit 0
fi

run_case() {
  value=$1
  label=$2
  rm -f "$TARGET_FILE"

  # sandbox-exec supports -D key=value for params on some systems. If the
  # option is unsupported, this will fail and we report that reality.
  sandbox-exec -D "ALLOW_DOWNLOADS=$value" -f "$PROFILE" -- /bin/sh -c "echo run-$label > \"$TARGET_FILE\"" \
    >/dev/null 2>&1
  rc=$?
  if [ -f "$TARGET_FILE" ]; then
    note="file created ($(cat "$TARGET_FILE"))"
  else
    note="no file created"
  fi
  printf "Param=%s -> exit %d (%s)\n" "$value" "$rc" "$note"
}

echo "SBPL param demo (TARGET=$TARGET_FILE)"
run_case "1" "with_param"
run_case "0" "without_param"

echo "
Notes:
- Parameters differ from entitlements or extensions: they are compile/evaluation
  time switches baked into the policy graph, not runtime metadata or tokens.
- System profiles often rely on params, but userland tooling exposes them only
  partially; if -D is unsupported on your macOS build, expect both runs to fail.
"
