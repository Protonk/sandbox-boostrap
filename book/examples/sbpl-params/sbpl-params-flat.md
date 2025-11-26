## 1. What this example is about

This example demonstrates **SBPL parameters** via `(param "...")` and how they can be toggled (where supported) using `sandbox-exec -D`.

Key ideas:

* Parameters are **compile/evaluation-time switches** embedded in the profile.
* The same SBPL text can yield **different effective policies** depending on how params are set.
* Params are distinct from:

  * **Entitlements** (code-signing metadata),
  * **Extensions** (runtime tokens).
* The script drives a minimal profile where one parameter, `ALLOW_DOWNLOADS`, gates write access to a directory under `/tmp`.

You can treat `params_demo.sh` as a small experiment: fix the profile, vary the parameter value, and observe whether a file write is allowed.

---

## 2. How to run and what to expect

From the example directory:

```sh
chmod +x params_demo.sh
./params_demo.sh
```

Behavior:

1. The script generates a temporary SBPL file in `/tmp/params-demo.XXXXXX.sb`.
2. It creates `/tmp/params-allowed/`.
3. It runs two test cases under `sandbox-exec`, with `ALLOW_DOWNLOADS` set to `"1"` and `"0"` respectively.
4. For each case it prints:

   ```text
   Param=1 -> exit <code> (file created / no file created)
   Param=0 -> exit <code> (file created / no file created)
   ```

If `sandbox-exec` is not available:

* The script prints that fact.
* It dumps the generated profile so you can inspect the `(param "ALLOW_DOWNLOADS")` usage.

If your macOS build does not support `sandbox-exec -D`, both runs may behave identically (typically both deny); the script notes this limitation in its final message.

---

## 3. The parameterized SBPL profile

The script writes this profile into a temporary file:

```scheme
(version 1)
(allow default)
;; Parameters appear as predicates in the graph; here they gate write access
;; to a single directory. Without ALLOW_DOWNLOADS, writes are denied.
(deny file-write* (subpath "/tmp/params-allowed"))
(allow file-write*
  (require-all
    (param "ALLOW_DOWNLOADS")
    (subpath "/tmp/params-allowed")))
```

Step-by-step:

1. **Baseline policy**

   ```scheme
   (version 1)
   (allow default)
   ```

   * Version 1 SBPL.
   * Default policy: allow everything unless explicitly denied.
   * This is the opposite of the usual `(deny default)` examples; the profile starts permissive and then adds a deny, then a conditional allow.

2. **Unconditional deny for the target directory**

   ```scheme
   (deny file-write* (subpath "/tmp/params-allowed"))
   ```

   * Denies all `file-write*` operations under `/tmp/params-allowed`, regardless of parameter value.
   * This creates a **baseline deny** for writes to the target directory.

3. **Conditional allow gated by a parameter**

   ```scheme
   (allow file-write*
     (require-all
       (param "ALLOW_DOWNLOADS")
       (subpath "/tmp/params-allowed")))
   ```

   * Allows `file-write*` only when:

     * The parameter `ALLOW_DOWNLOADS` is “on”, and
     * The path is under `/tmp/params-allowed`.

   * `(param "ALLOW_DOWNLOADS")` is a predicate in the compiled graph:

     * If the param is set (true) at compile/evaluation time, this branch can match.
     * If it is unset, the predicate fails, and the allow rule does not apply.

Effective behavior:

* Without the param:

  * `deny file-write* (subpath "/tmp/params-allowed")` is in effect.
  * No matching allow rule → writes are denied.
* With the param set:

  * The `allow` rule matches for `file-write*` into `/tmp/params-allowed`.
  * Depending on rule ordering and combining semantics, this serves as a conditional override for that directory.

Conceptually, this shows **how one SBPL file can represent multiple policies** depending on parameter configuration.

---

## 4. The shell harness (`params_demo.sh`)

### 4.1 Setup and profile generation

```sh
PROFILE=$(mktemp /tmp/params-demo.XXXXXX.sb)
TARGET_DIR="/tmp/params-allowed"
TARGET_FILE="$TARGET_DIR/from_param.txt"
mkdir -p "$TARGET_DIR"
cleanup() { rm -f "$PROFILE"; }
trap cleanup EXIT
```

* `PROFILE`: temporary SBPL file path.
* `TARGET_DIR`: directory whose writes are gated by the param.
* `TARGET_FILE`: the file the demo attempts to create.
* The script ensures:

  * Directory exists.
  * Temporary profile file is cleaned up on exit.

### 4.2 Handling missing `sandbox-exec`

```sh
if ! command -v sandbox-exec >/dev/null 2>&1; then
  echo "sandbox-exec not available; showing the parameterized profile instead:"
  cat "$PROFILE"
  exit 0
fi
```

If `sandbox-exec` is not present:

* The script prints the profile and exits.
* This lets you study the `(param "...")` pattern even on systems without `sandbox-exec`.

### 4.3 Running with different parameter values

The core experiment is encapsulated in `run_case`:

```sh
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
```

What it does:

1. Takes a parameter value and a label (`with_param`, `without_param`).

2. Removes any existing `$TARGET_FILE`.

3. Runs:

   ```sh
   sandbox-exec -D "ALLOW_DOWNLOADS=$value" \
     -f "$PROFILE" -- /bin/sh -c "echo run-$label > \"$TARGET_FILE\""
   ```

   * `-f "$PROFILE"`: use the generated SBPL file.
   * `-D "ALLOW_DOWNLOADS=$value"`: attempt to set the parameter `ALLOW_DOWNLOADS` to `"0"` or `"1"`.

4. Captures the exit code.

5. Checks whether the target file exists and, if so, what it contains.

6. Prints a summary line reporting:

   * The parameter value,
   * The exit code,
   * Whether the write succeeded (file created) or not.

The `-D` comment signals an important caveat:

* `sandbox-exec -D` parameter support is **not uniform across macOS versions**.
* On some builds, the flag may be unsupported or ignored.
* In those cases, both runs may yield the same behavior, regardless of `value`.

The script’s final notes reiterate this.

### 4.4 Top-level driver

```sh
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
```

* First, it prints the target path.
* Then it runs:

  * `Param=1` (expected “allow” path, if `-D` works).
  * `Param=0` (expected “deny” path).
* Finally, it reminds you of the conceptual distinctions and the tooling limitations.

---

## 5. How to use this example for learning

Ways to exploit this example:

1. **Observe parameter effects directly**

   * Run `params_demo.sh` and compare the result lines.
   * If `-D` is supported:

     * Expect `Param=1` run to create the file.
     * Expect `Param=0` run not to create it.
   * This shows how a single profile can encodes both behaviors, with params selecting one.

2. **Inspect the compiled graph**

   * Compile the profile via `sandbox-exec` or a separate `libsandbox` helper.
   * Use your ingestion / graph tools to inspect the compiled representation:

     * Look for a node or predicate corresponding to `(param "ALLOW_DOWNLOADS")`.
     * Note how the parameter node interacts with the `file-write*` op and `subpath` predicate.

3. **Relate params to other inputs**

   * Compare this example with:

     * **Entitlement-driven** examples (`entitlements-evolution`),
     * **Extension-driven** examples (`extensions-dynamic`).
   * Distinguish:

     * Params: static, profile-level switches.
     * Entitlements: code-signing metadata used by platform/App Sandbox.
     * Extensions: runtime tokens that temporarily widen the sandbox.

4. **Modify the profile**

   * Change the param name, add more param-based branches, or combine with metafilters.
   * Re-run the script (or adapt it) to test more complex parameterized behaviors.

This example makes SBPL parameters concrete: you see `(param "...")` in the policy, drive it via `sandbox-exec -D`, and verify whether writes into a specific directory succeed or fail, while keeping the SBPL text fixed.
