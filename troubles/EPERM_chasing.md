# EPERM when applying system blobs (`airlock.sb.bin`, `bsd.sb.bin`)

## What and where
- **Surface:** Applying compiled system sandbox blobs (`airlock.sb.bin`, `bsd.sb.bin`) via `sandbox_apply` in `book/api/SBPL-wrapper/wrapper --blob` under the `runtime-checks` harness.
- **Symptom:** `sandbox_apply` returns `EPERM` before exec. Custom blobs (e.g., `allow_all.sb.bin` from `sbpl-graph-runtime`) apply cleanly.
- **Host:** macOS 14.4.1 (23E224), Apple Silicon, SIP on (danger-full-access in Codex).
- **Profiles:** Shipped blobs from `book/examples/extract_sbs/build/profiles/` (extracted from `/System/Library/Sandbox/Profiles/*.sb.bin` via `extract_sbs` helper).

## Substrate framing
- **Profile layers & provenance:** Orientation/Concepts treat platform profiles (airlock/bsd) as platform-layer policies attached by secinit/sandboxd with platform credentials. The effective policy stack installs these as part of the platform label, not ad hoc.
- **Enforcement:** Seatbelt installs compiled PolicyGraphs keyed by operation IDs; apply failures (`EPERM`) happen before operation graph evaluation. Policy Stack Evaluation Order assumes platform profiles come from trusted sources; ad hoc apply from a non-platform process may be rejected.
- **Adjacent controls:** SIP/hardened runtime may gate certain kernel interactions; however, SBPL parsing is bypassed here (blobs), so provenance checks or profile-type flags are the likely cause, not SBPL contents.

## Steps taken
- **Wrapper path:** Wired `run_probes.py` to use `book/api/SBPL-wrapper/wrapper --blob` for blob-mode profiles. `sandbox_apply` returns `EPERM` only for system blobs; custom blobs succeed.
- **Header inspection:** Used `book.api.decoder` (with new header exposure) to dump preamble/flags:
  - `airlock`: `maybe_flags=0x4000`, `op_count=167`, `magic=0x00be`.
  - `bsd`: `maybe_flags=0x0000`, `op_count=28`, `magic=0x00be`.
  - `allow_all` (custom): `maybe_flags=0x0000`, `op_count=2`, `magic=0x00be`.
  - Only clear discriminator so far is `0x4000` on `airlock`; `bsd` matches custom on flags yet still EPERMs.
- **SBPL fallback:** Applying SBPL text via `sandbox_init` works for synthetic/custom profiles; system SBPL imports were used previously but are now routed through blob mode and fail at apply.

## What the substrate implies
- Platform profile layers are expected to be installed by platform mechanisms (secinit/sandboxd) with platform credentials. Ad hoc `sandbox_apply` from a non-platform process may be refused regardless of profile content (provenance check).
- Profile-layer provenance may be encoded in header fields/flags and/or enforced out-of-band (caller credentials). EPERM here fits a “platform-only” gate.

## Impact / blocked work
- **runtime-checks experiment:** System profiles (`sys:airlock`, `sys:bsd`) record apply-fail denies; cannot validate runtime behavior of platform policies via blob mode on this host.
- **sbpl-graph-runtime (if extended to system profiles):** Blob-mode runtime triples for platform profiles blocked.
- **Blob-mode validation generally:** Cannot use shipped blobs for platform/system profiles without resolving the apply gate; SBPL imports remain a workaround but may lose fidelity if compiler behavior differs.

## Open questions
- Is there a header flag (e.g., word0 `0x4000` or others) marking platform-only blobs that the kernel enforces?
- Does `sandbox_apply_container` behave differently for these blobs?
- Would recompiled SBPL versions of `bsd`/`airlock` apply via `sandbox_apply` (i.e., is the gate tied to shipped provenance vs profile content)?
- Is EPERM purely caller-credential based (platform bits missing) rather than header-based?

---

### Response (verbatim)

First, an observation: the “maybe_flags” field you saw in the preamble is almost certainly a red herring for the EPERM. On modern `.sb.bin` profiles, Word 0 in the header is usually a size/flags word for the serialized format itself, not a policy type indicator. If you compare across many modern blobs, you’ll see that lots of non-platform profiles carry a high bit in word 0 when they have embedded literal/regex tables above certain sizes. So, treat the 0x4000 on `airlock` as “format quirk” until proven otherwise.

Now, the bad news: `sandbox_apply` refusing platform/system blobs is a documented phenomenon in the wild. Apple never intended third-party code to apply arbitrary platform bundles; libsandbox enforces provenance in multiple ways:

* It checks the caller’s code signature / platform bit. Calls from non-platform processes trying to install a “platform class” profile return `EPERM`.
* It checks profile class in the blob (not always visible in a shallow header dump). There is usually a “profile type” word later in the header or in the serialized node table that distinguishes platform profiles from user/app profiles. If that class is “platform” and you’re not a platform caller, you get `EPERM`.
* On some builds, even non-platform profiles are rejected if the blob didn’t come from the current `Seatbelt` bundle (libsandbox validates provenance against a whitelist of compiled-in hashes). This is the “blob provenance” gate documented in some macOS security talks.

There are a couple of ways people have worked around this in practice:

1. **Recompile the SBPL**. If the text SBPL exists (it does for `airlock.sb` and `bsd.sb` on macOS), recompile it via `sandbox_compile_string` and apply the resulting blob. The freshly compiled blob is classed as a “user” profile and will usually apply, even if the shipped platform blob does not.
2. **Use `sandbox_init` on SBPL text**. This is the supported path; libsandbox accepts the text and installs the compiled policy under the caller’s label. This sidesteps the blob provenance checks entirely (you’re not applying the shipped blob; you’re compiling your own).
3. **Use `sandbox_apply_container`**. In some OS versions, `sandbox_apply_container` is laxer about profile class than `sandbox_apply`. On others, it still checks platform bits. But it’s worth probing: call `sandbox_apply_container(blob, flags=0)` and see if it returns something other than `EPERM`.
4. **Run as a platform process**. If you launch your wrapper from a platform-signed binary with the platform bit set (e.g., via a small helper signed with Apple’s platform cert), `sandbox_apply` will accept the platform blob. Obviously not feasible for most third-party contexts.

Key takeaway: `EPERM` on `airlock.sb.bin`/`bsd.sb.bin` is the expected behavior when applying platform blobs from a non-platform caller. You will not find a “magic flag” in the first 64 bytes that, if tweaked, makes `sandbox_apply` accept them; libsandbox validates both caller credentials and internal profile class.

What to do next, given your tooling/goal:

* **For runtime checks**, fall back to SBPL text for system profiles: `(import "/System/Library/Sandbox/Profiles/bsd.sb")` etc., and apply via `sandbox_init` or by recompiling the SBPL into a user-class blob before applying. That will get you runtime behavior without the provenance gate.
 * **For header curiosity**, extend your decoder to dump the “profile class/type” field. It’s usually at a fixed offset beyond the initial preamble (on iOS/macOS 14-era blobs, it’s a 16-bit value in the header region; values like 0/1/2 map to user/app/platform). You’ll need to look past the op-table to find it (search for small integers near the preamble). That field, combined with caller credentials, drives the EPERM decision.
 * **For completeness**, try `sandbox_apply_container` with flags=0 against your blobs and log errno. It might be less strict on this OS build, but don’t count on it.

### Current follow-up findings (this host)

- Decoder heuristic now surfaces `profile_class` (searching early header words). All inspected blobs (`airlock`, `bsd`, `allow_all`, and recompiled system SBPL) report `profile_class=0`; `maybe_flags=0x4000` only on `airlock`.
- Recompiling system SBPL via `sandbox_compile_string` does not bypass the gate: `bsd` applies (`sandbox_apply rc=0`; `sandbox_init rc=0`), `airlock` still fails (`sandbox_apply rc=-1`/`EPERM`; `sandbox_init` also fails). Applying shipped `airlock` blob via wrapper also fails with `EPERM`; `bsd` blob path was blocked by execvp noise but SBPL/compile shows it is applicable.
- Conclusion to date: on this host, `airlock` remains platform-only (EPERM) even when recompiled; `bsd` is usable via SBPL/recompiled blob. Platform provenance gating likely enforced by caller credentials and/or deeper profile metadata not yet decoded.
