## 1. What this example is about

This example is a small, focused lab for **SBPL metafilters**: `require-any`, `require-all`, and `require-not`.

It uses:

* Short, self-contained sandbox profiles that only touch `file-read*`.
* `sandbox-exec` as a harness to run `/bin/cat` under those profiles.
* Controlled test files and symlinks in `/tmp`.

The goal is to make the boolean structure of these metafilters visible in practice:

* OR: deny if **any** of several predicates match.
* AND: deny only when **all** predicates hold simultaneously.
* NOT: deny based on the **inverse** of a predicate.

You can read `metafilter_demo.sh` as a scripted notebook: it sets up data, defines tiny profiles, runs tests, and prints out the results with expectations.

---

## 2. How to run and what to expect

From the example directory:

```sh
chmod +x metafilter_demo.sh
./metafilter_demo.sh
```

Possible outcomes:

* If `sandbox-exec` is not available:

  * The script prints a message and exits early.
  * You can still inspect the generated profiles in the temp directory by commenting out the `exit 0` and printing their paths.

* If `sandbox-exec` is available:

  * The script:

    * Creates test files and symlinks under `/tmp`.
    * Writes three SBPL profiles into a temporary directory.
    * Runs `sandbox-exec` with each profile and target file.
    * For each test, prints something like:

      ```
      [require-any] cat /tmp/metafilter_any_ok -> exit 0 (expected allow)
      [require-any] cat /tmp/metafilter_any_block_me -> exit 1 (expected deny)
      ```

The exit codes (0 for success, non-zero for denial) let you see how each metafilter changes behavior.

---

## 3. High-level script structure

`metafilter_demo.sh` has four main phases:

1. Check for `sandbox-exec`.
2. Create a temporary directory and test inputs.
3. Generate three tiny profiles:

   * `require-any.sb`
   * `require-all.sb`
   * `require-not.sb`
4. Run a series of `sandbox-exec` test cases and print results.

You can treat each profile as a separate “metafilter experiment” while keeping all other conditions constant.

---

## 4. Environment and setup

### 4.1 Check for `sandbox-exec`

```sh
if ! command -v sandbox-exec >/dev/null 2>&1; then
  echo "sandbox-exec not available on this system; showing profile contents only."
  exit 0
fi
```

* If `sandbox-exec` is missing, the script exits.
* This avoids confusing failures later.

### 4.2 Temporary directory and cleanup

```sh
TMPDIR=$(mktemp -d /tmp/metafilter-demo.XXXXXX)
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT
```

* Creates a fresh temp directory for the SBPL profiles.
* Registers a `trap` to remove it on exit.
* Keeps the example self-contained and avoids piling up temp files.

### 4.3 Test files and symlinks

The script creates three groups of test paths:

1. **`require-any` targets**

   ```sh
   echo "allowed content" > /tmp/metafilter_any_ok
   echo "blocked content" > /tmp/metafilter_any_block_me
   echo "blocked too" > /tmp/metafilter_any_also_block
   ```

   * One file intended to be allowed.
   * Two files intended to be denied by the OR metafilter.

2. **`require-all` targets**

   ```sh
   mkdir -p /tmp/metafilter_all
   echo "real file" > /tmp/metafilter_all/real.txt
   ln -sf /tmp/metafilter_all/real.txt /tmp/metafilter_all/link.txt
   ```

   * A real regular file.
   * A symlink pointing at that file.
   * The AND metafilter will treat “under this subpath” + “is a symlink” specially.

3. **`require-not` targets**

   ```sh
   mkdir -p /tmp/metafilter_not
   echo "plain file" > /tmp/metafilter_not/plain.txt
   ln -sf /tmp/metafilter_not/plain.txt /tmp/metafilter_not/symlink.txt
   ```

   * Another real regular file and symlink in a different directory.
   * The NOT metafilter will invert a `vnode-type` condition under this subpath.

These paths are the “inputs” for the boolean logic you’re testing.

---

## 5. The SBPL profiles

Each profile:

* Starts with `(version 1)` and `(allow default)`.
* Adds one focused `deny file-read*` rule using the metafilters.

Using `(allow default)` keeps the harness runnable but lets you see targeted denies clearly.

### 5.1 `require-any.sb` – logical OR

```lisp
(version 1)
(allow default)
;; Deny reads to two literals if either matches (logical OR).
(deny file-read*
  (require-any
    (literal "/tmp/metafilter_any_block_me")
    (literal "/tmp/metafilter_any_also_block")))
```

Interpretation:

* By default, file reads are allowed.
* The `deny file-read*` applies only when `require-any` matches.
* `require-any` wraps two `literal` filters:

  * If the path equals `/tmp/metafilter_any_block_me` OR `/tmp/metafilter_any_also_block`, the deny branch is taken.
* `"/tmp/metafilter_any_ok"` does not match either literal, so it remains allowed.

Conceptually, this is the **OR** metafilter:

* “Deny reads if any of these path predicates are true.”

### 5.2 `require-all.sb` – logical AND

```lisp
(version 1)
(allow default)
;; Deny reads when BOTH the path is under /tmp/metafilter_all AND it is a symlink.
(deny file-read*
  (require-all
    (subpath "/tmp/metafilter_all")
    (vnode-type SYMLINK)))
```

Interpretation:

* Again, default allow.
* The denial applies only when both child filters match:

  * The path is under `/tmp/metafilter_all`.
  * The vnode type is `SYMLINK`.
* Consequences:

  * `/tmp/metafilter_all/real.txt`:

    * Under the subpath? Yes.
    * Is it a symlink? No → **allow**.
  * `/tmp/metafilter_all/link.txt`:

    * Under the subpath? Yes.
    * Is it a symlink? Yes → **deny**.

Conceptually, this is the **AND** metafilter:

* “Deny only when all child predicates hold simultaneously.”

### 5.3 `require-not.sb` – logical NOT (with AND)

```lisp
(version 1)
(allow default)
;; Deny reads for non-regular files under /tmp/metafilter_not (NOT regular-file).
(deny file-read*
  (require-all
    (subpath "/tmp/metafilter_not")
    (require-not (vnode-type REGULAR-FILE))))
```

Interpretation:

* Default allow again.
* Deny when both:

  * The path is under `/tmp/metafilter_not`.
  * The inner `require-not` matches, which flips the meaning of `(vnode-type REGULAR-FILE)`.

So:

* If vnode is a regular file:

  * `(vnode-type REGULAR-FILE)` matches.
  * `require-not` of that is false.
  * Combined with the AND, the whole deny condition fails → **allow**.
* If vnode is not a regular file (e.g., a symlink):

  * `(vnode-type REGULAR-FILE)` does not match.
  * `require-not` sees that as success.
  * Under the subpath + NOT regular-file → deny.

Applied to the test files:

* `/tmp/metafilter_not/plain.txt`:

  * Under the subpath and a regular file → **allow**.
* `/tmp/metafilter_not/symlink.txt`:

  * Under the subpath and a symlink (non-regular) → **deny**.

Conceptually, this shows **NOT**:

* `require-not` inverts a nested filter, but in compiled graphs this is represented via control-flow structure, not an explicit “NOT” opcode.

---

## 6. The test harness

### 6.1 `run_case` helper

```sh
run_case() {
  profile=$1
  label=$2
  target=$3
  expected=$4

  sandbox-exec -f "$profile" -- /bin/cat "$target" >/dev/null 2>&1
  rc=$?
  printf "[%s] cat %s -> exit %d (expected %s)\n" "$label" "$target" "$rc" "$expected"
}
```

This function:

* Runs `/bin/cat target` under `sandbox-exec -f profile`.
* Ignores stdout/stderr, capturing only the exit code.
* Prints:

  * which metafilter is being tested (`label`),
  * the target path,
  * the actual exit code,
  * the expected result (“allow” or “deny”).

Exit code semantics:

* `0` → cat succeeded → sandbox allowed the read.
* Non-zero (usually 1 when denied by sandbox) → failure → treat as “deny”.

### 6.2 Running the three metafilter suites

```sh
echo "Testing require-any (OR)"
run_case "$PROFILE_ANY" "require-any" "/tmp/metafilter_any_ok" "allow"
run_case "$PROFILE_ANY" "require-any" "/tmp/metafilter_any_block_me" "deny"

echo "\nTesting require-all (AND)"
run_case "$PROFILE_ALL" "require-all" "/tmp/metafilter_all/real.txt" "allow"
run_case "$PROFILE_ALL" "require-all" "/tmp/metafilter_all/link.txt" "deny"

echo "\nTesting require-not (NOT)"
run_case "$PROFILE_NOT" "require-not" "/tmp/metafilter_not/plain.txt" "allow"
run_case "$PROFILE_NOT" "require-not" "/tmp/metafilter_not/symlink.txt" "deny"
```

For each metafilter:

* One “should be allowed” case.
* One “should be denied” case.

This pattern isolates **just** the boolean logic; filesystem paths and operations are otherwise held constant.

### 6.3 Summary

The script ends with a recap:

```sh
echo "
Metafilter takeaway:
- require-any: matching any child filter triggers the branch (OR).
- require-all: every child must match to hit the deny branch (AND).
- require-not: flips the sense of the nested filter; in compiled graphs this is
  just control-flow structure, not an explicit NOT opcode (see substrate/Appendix.md).
"
```

This connects back to the lesson that:

* Metafilters are **syntax-level combinators** in SBPL.
* In the compiled profile graph, they show up as specific control-flow shapes, not as standalone “metafilter nodes”.

---

## 7. How to use this example for learning

Practical ways to use this example:

1. **Run it as-is and confirm expectations**

   * Check that each `[label] cat path -> exit` line matches the expected allow/deny.
   * This builds intuition about `require-any/all/not` on simple path and vnode-type predicates.

2. **Inspect the generated profiles**

   * While the script is running (or by commenting out `trap cleanup EXIT`), inspect the SBPL files in `$TMPDIR`.
   * Compare them directly to the graphs you get if you compile and disassemble them via your own tooling.

3. **Modify predicates**

   * Change the profiles to:

     * Add more children under `require-any`.
     * Change `vnode-type` predicates.
     * Use different paths or subpaths.
   * Re-run and observe how the behavior changes.

4. **Map to decoded graphs**

   * Compile these tiny profiles to binary form and inspect them with your graph tools.
   * Look for the OR/AND/NOT structures in the node graph, noting that there is no dedicated “metafilter opcode”; only control-flow shape encodes the boolean logic.

Overall, `metafilter_demo.sh` is a small, concrete harness that turns metafilters from abstract SBPL syntax into observable behavior and graph patterns, helping to reduce “why was this path denied?” confusion when reading more complex profiles.
