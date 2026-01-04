# Temp-exception adapter asymmetry (mach-lookup vs mach-register)

## Scope

This report proposes a compact, inspectable tour of the issue: the SBPL language can express both exact (`global-name`) and prefix (`global-name-prefix`) filters for both `mach-lookup` and `mach-register`, but the *temporary-exception entitlement adapters* in Apple’s stock App Sandbox profile wire these two ops differently. The tour favors tiny tools and small artifacts, and it keeps every claim tied to host-scoped evidence (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).

Primary source for profile wiring is the live system profile at `/System/Library/Sandbox/Profiles/application.sb`. Where outputs exist, they are captured under `status/mach-asymmetry/` or at the evidence paths called out in each unit.

## Tour overview

Units are ordered from static text → vocabulary → decision witness → syscall witness. Each unit stands alone and can be inspected without bootstrapping the rest, and the outputs are plain text to keep review simple.

### Unit 1: Adapter wiring (tiny extractor + text snippets)

**Goal:** Show that the temporary-exception adapter for `mach-register` uses `select-mach-filter` (trailing `*` → `global-name-prefix`), while the temporary-exception adapter for `mach-lookup` uses exact `global-name`. This is the narrowest textual root of the asymmetry.

**Tiny tool:** a short snippet extractor that prints the three relevant sections from the system profile.

```sh
PROFILE="/System/Library/Sandbox/Profiles/application.sb"
{
  # Helper that converts a trailing "*" to a prefix filter.
  echo "== select-mach-filter =="
  sed -n '20,60p' "$PROFILE"
  echo
  # App-group stanza: prefix lookup exists in stock policy.
  echo "== app group global-name-prefix =="
  sed -n '320,360p' "$PROFILE"
  echo
  # Temporary-exception adapters: the asymmetric wiring.
  echo "== temporary-exception adapters =="
  sed -n '860,900p' "$PROFILE"
} > status/mach-asymmetry/adapter_snips.txt
```

**Artifact:** `status/mach-asymmetry/adapter_snips.txt`

**Expected reading:**  
- `select-mach-filter` chooses `global-name-prefix` when an entitlement value ends with `*`.  
- `com.apple.security.temporary-exception.mach-register.global-name` routes through `select-mach-filter`.  
- `com.apple.security.temporary-exception.mach-lookup.global-name` uses exact `(global-name name)` with no wildcard handling.  
- App groups grant **both** `mach-lookup` and `mach-register` with `global-name-prefix`.

### Unit 2: SBPL expressiveness (vocab presence)

**Goal:** Show that `global-name` and `global-name-prefix` are distinct Filters in the host’s vocabulary, and that both `mach-lookup` and `mach-register` are Operations on this host.

**Tiny tool:** `jq` extracts from the vocab mappings.

```sh
# Filters: exact vs prefix are distinct in the host vocab.
jq -r '.filters[] | select(.name == "global-name" or .name == "global-name-prefix")' \
  book/integration/carton/bundle/relationships/mappings/vocab/filters.json

# Operations: both publish and resolve are present on this host.
jq -r '.ops[] | select(.name == "mach-lookup" or .name == "mach-register")' \
  book/integration/carton/bundle/relationships/mappings/vocab/ops.json
```

**Artifact:** `status/mach-asymmetry/vocab_snips.txt` (frozen copy of the outputs above).

**Expected reading:** the SBPL language supports both exact and prefix filters for Mach service names; nothing in the vocabulary prevents prefix lookup in principle.

### Unit 3: Decision witness (literal `*` vs prefix)

**Goal:** Demonstrate that `(global-name "AA*")` treats `*` as a literal character in decision checks, while `(global-name-prefix "AA")` matches `AA<suffix>`. This is not about entitlements yet; it is a direct SBPL semantics witness, and it isolates `mach-lookup` by denying it globally first.

**Tiny tool:** a minimal C program that selects an `exact` or `prefix` profile at runtime (run it twice) and prints a small `sandbox_check` matrix for `mach-lookup` with `AA`, `AA*`, and `AA<pid>`; it uses allow-default plus an explicit `mach-lookup` deny so only the listed allow rule matters.

```c
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum sandbox_filter_type { SANDBOX_FILTER_GLOBAL_NAME = 2 }; /* sandbox_check ABI */
extern int sandbox_check(pid_t pid, const char *operation, enum sandbox_filter_type type, ...);
extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
                                       const char *const parameters[], char **errorbuf);
extern void sandbox_free_error(char *errorbuf);

static int apply_profile(const char *profile) {
  const char *params[] = { NULL };
  char *err = NULL;
  int rc = 0;
  /* Apply in-memory SBPL to avoid file I/O confounders. */
  rc = sandbox_init_with_parameters(profile, 0x0000, params, &err);
  if (rc != 0) {
    fprintf(stderr, "sandbox_init_with_parameters failed rc=%d err=%s\n",
            rc, err ? err : "(null)");
    if (err) sandbox_free_error(err);
    return rc;
  }
  if (err) sandbox_free_error(err);
  return 0;
}

static void check(const char *op, const char *name) {
  errno = 0;
  int rc = sandbox_check(getpid(), op, SANDBOX_FILTER_GLOBAL_NAME, name);
  /* rc=0 allow, rc=1 deny; errno only matters when rc == -1. */
  printf("%s name=\"%s\" rc=%d errno=%d\n", op, name, rc, errno);
}

static void usage(const char *prog) {
  fprintf(stderr, "Usage: %s <exact|prefix>\n", prog);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    usage(argv[0]);
    return 64;
  }

  const char *mode = argv[1];
  const char *aa = "com.example.rendezvous";
  char bb[128];
  char star[128];

  /* Keep AA, AA*, and BB in the same process (shared PID). */
  snprintf(bb, sizeof(bb), "%s.%d", aa, (int)getpid());
  snprintf(star, sizeof(star), "%s*", aa);

  char profile[512];
  if (strcmp(mode, "exact") == 0) {
    /* Allow-default keeps the profile minimal; the op is still gated by the deny below. */
    snprintf(profile, sizeof(profile),
             "(version 1)\n"
             "(allow default)\n"
             "(deny mach-lookup)\n"
             "(allow mach-lookup (global-name \"%s\"))\n",
             star);
  } else if (strcmp(mode, "prefix") == 0) {
    snprintf(profile, sizeof(profile),
             "(version 1)\n"
             "(allow default)\n"
             "(deny mach-lookup)\n"
             "(allow mach-lookup (global-name-prefix \"%s\"))\n",
             aa);
  } else {
    usage(argv[0]);
    return 64;
  }

  if (apply_profile(profile) != 0) {
    /* Surface apply failures; do not emit a misleading matrix. */
    return 2;
  }
  /* Self-describing output to simplify diffing. */
  printf("mode=%s pid=%d\n", mode, (int)getpid());
  printf("AA=%s\n", aa);
  printf("AA_star=%s\n", star);
  printf("BB=%s\n", bb);
  check("mach-lookup", aa);
  check("mach-lookup", star);
  check("mach-lookup", bb);

  return 0;
}
```

**Artifact:** `status/mach-asymmetry/lookup_star_matrix.txt` (captured output), with per-mode stdout files alongside; source is `status/mach-asymmetry/lookup_star_matrix.c`, and if `sandbox_init_with_parameters` fails in a shell, run the binary via launchctl or a clean channel.

Excerpt from `status/mach-asymmetry/lookup_star_matrix.txt`:

```text
== exact ==
mode=exact pid=2589
AA=com.sandboxlore.rendezvous
AA_star=com.sandboxlore.rendezvous*
BB=com.sandboxlore.rendezvous.2589
mach-lookup name="com.sandboxlore.rendezvous" rc=1 errno=0
mach-lookup name="com.sandboxlore.rendezvous*" rc=0 errno=0
mach-lookup name="com.sandboxlore.rendezvous.2589" rc=1 errno=0
== prefix ==
mode=prefix pid=2601
AA=com.sandboxlore.rendezvous
AA_star=com.sandboxlore.rendezvous*
BB=com.sandboxlore.rendezvous.2601
mach-lookup name="com.sandboxlore.rendezvous" rc=0 errno=0
mach-lookup name="com.sandboxlore.rendezvous*" rc=0 errno=0
mach-lookup name="com.sandboxlore.rendezvous.2601" rc=0 errno=0
```

**Expected reading:** under `global-name`, `*` is literal (so only the literal `AA*` is allowed), and `AA<pid>` is denied; under `global-name-prefix`, `AA`, `AA*`, and `AA<pid>` all allow because the prefix matches each.

### Unit 4: Publish syscall witness (bootstrap_register)

**Goal:** Provide a syscall-level witness for `mach-register` that does not rely on `sandbox_check`.

**Tiny tool + artifact (already exists):**
- Source: `book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/second_opinion/67efb8e1-387e-4c0d-99b5-954b8898685d/mach_name_register_witness.c`
- Output: `book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/second_opinion/67efb8e1-387e-4c0d-99b5-954b8898685d/sandbox.stdout.txt`

**Expected reading:** `bootstrap_register` succeeds for AA and fails for BB when the SBPL profile allows `mach-register` only for AA (`global-name`), and both succeed without sandboxing; the sandboxed BB failure is `kr=1100` (BOOTSTRAP_NOT_PRIVILEGED). This is the syscall counterpart to the decision-level split.

### Unit 5: Prefix lookup exists (app groups)

**Goal:** Show that prefix lookup is used in stock policy outside the temporary-exception adapters.

**Tiny tool:** reuse Unit 1’s snippet output; focus on the app-group stanza where both `mach-lookup` and `mach-register` are allowed with `global-name-prefix` under `suite "."`.

**Expected reading:** prefix matching is not a property of `mach-register` alone; `mach-lookup` can use `global-name-prefix` in SBPL and does so in `application.sb`, as shown in `status/mach-asymmetry/adapter_snips.txt`.

## Proposed narrative (one-liner summary)

The asymmetry is not in the operations themselves but in the **temporary-exception entitlement adapters**: `mach-register` uses `select-mach-filter` (so `*` becomes `global-name-prefix`), while `mach-lookup` uses exact `global-name`; elsewhere in `application.sb` (e.g., app groups), `mach-lookup` *does* use `global-name-prefix`. The right diagnosis is entitlement-surface asymmetry, not operation-semantics asymmetry.

## Footnote: profile copy parity

The repo copy `book/evidence/profiles/textedit/application.sb` is not bit-identical to `/System/Library/Sandbox/Profiles/application.sb` on this host (hashes differ). The snippets relevant to this issue (`select-mach-filter`, the app-group `global-name-prefix` rule, and both temporary-exception adapters) are identical in both copies, so the adapter asymmetry described here is the same either way and this tour uses the system profile for fidelity.
