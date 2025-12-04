
## Chat agent readout

The thread started with the user asking whether the web agent understood a project-local notion of “field2.” The web agent answered that it did not and asked for a restatement in local terms. The user provided a compact definition:

* In decoded policy graphs, each node record has two edge pointers and a third 16-bit “payload” field, called `field2`.
* For many nodes, `field2` matches known filter IDs from the harvested vocabulary (path, mount-relative-path, global/local-name, socket-type, etc.) and lines up with system profiles.
* Some nodes carry higher `field2` values that do not map to this vocabulary and only appear in richer graphs: flow-divert probes (~2560), bsd tail (~170/174/115/109/16660), airlock (~165/166/10752).

The user explicitly instructed the web agent to ask one or two questions that a local codex agent could answer. From that point on, most of the thread was message passing between:

* a web agent with internet access and Seatbelt background, and
* a codex agent operating on the actual repo, decoded graphs, and Ghidra/KC, following the web agent’s instructions and reporting back.

The human user helped set up the pattern, then largely stayed out of the way.

With the local definition in hand, the web agent:

* Mapped `field2` to the canonical `filter_arg` field from older reverse-engineering work (third 16-bit payload alongside tag/opcode and filter id).
* Checked public material for Sonoma-era changes and any explicit mapping of high payload values (such as 0x0a00 or 0x4114) to concrete filters or branches.

From that survey, the agent concluded:

* Public sources still describe this slot only as “filter-specific payload / argument,” not a structurally new field.
* There is no published Sonoma-specific mapping for the high payload values the user observed.
* It remains compatible with public writing that:
  * internal filters and profile-local predicates exist beyond the public SBPL vocabulary, and
  * the payload could carry flags or indices, but those encodings are undocumented.

Given the local summary from decoded graphs—many nodes with `field2` matching known filter IDs and a sparse set of “high” values in richer graphs—the web agent suggested:

* Treat the slot as `filter_arg_raw` and derive `field2_hi = raw & 0xc000` / `field2_lo = raw & 0x3fff` as an analytic view, not an assumed kernel split.
* Let graph structure and role (shared tails, op coverage, tag layouts) drive any classification, rather than trying to guess meanings from the hex values alone.
* Use kernel-side evidence from the sandbox kext to see how this payload is actually read and whether any mask or bit-test pattern matches the hi/lo split.

Following that guidance, the codex agent grounded the conversation in the `field2-filters` experiment:

* Ran `harvest_field2.py` and `unknown_focus.py` across canonical system blobs and synthetic probes, capturing:
  * `out/field2_inventory.json` – per-profile histograms of `filter_arg_raw` values and hi/lo splits.
  * `out/unknown_nodes.json` – a list of “unknown” nodes with tag, fan-in/fan-out, and op reach.
* Confirmed that **low** `field2` IDs match the filter vocabulary on this Sonoma host, e.g.:
  * 0=path, 1=mount-relative-path, 3=file-mode, 5=global-name, 6=local-name, 7=local, 8=remote,
  * 11=socket-type, 17/18=iokit-*, 26/27=right-name/preference-domain, 80=mac-policy-name.

Those inventories then highlighted a small set of **high/unknown clusters**:

* In `bsd.sb.bin`:
  * one sentinel `16660` (`hi=0x4000`, `lo=0x0114`) on tag 0, with high fan-in and reachability from ops 0–27 (the default/file* cluster),
  * and a group `{170, 174, 115, 109}` on tag 26 with `fan_in=0`, `fan_out=1`, and no op reach.
* In `airlock.sb.bin` and its probe:
  * values `{165, 166, 10752}` on tags 166/1/0 tied to op 162 (`system-fcntl`),
  * plus a new `0xffff` sentinel (hi=0xc000) on tag 1 in the synthetic `airlock_system_fcntl` profile.
* In `sample.sb.bin`:
  * a single sentinel `3584` (`hi=0`, `lo=0x0e00`) on tag 0; the rest of the graph uses low IDs for path/local/remote.
* In flow-divert‑focused probes (`v4_network_socket_require_all`, `v7_file_network_combo`, `net_require_all_domain_type_proto`):
  * a node with `field2=2560` (`hi=0`, `lo=0x0a00`) on tag 0, structurally a trivial branch with both successors pointing at node 0,
  * that node appears only when socket domain, type, and protocol are all required together; any simpler profile collapses back to low IDs.

The web agent used these inventories and the `unknown_nodes.json` summaries to phrase the open questions more sharply: the interesting unknowns are rare, tied to specific tags and operations (bsd’s shared tail, airlock’s system-fcntl cluster, the flow-divert branch), and structurally well-bounded, but they do not yet line up with any named filter in the vocab maps.

To get kernel-side evidence, the codex agent needed to run Ghidra headless against the sandbox kext. The first batch of attempts hit the familiar obstacles also recorded in `troubles/ghidra_setup.md`:

* `analyzeHeadless` tried to prompt for a JDK path and failed with:
  * `java_home.save (Operation not permitted)` under the real `$HOME`,
  * `Unable to prompt user for JDK path, no TTY detected`.
* Without overriding `HOME`/`GHIDRA_USER_HOME`, Ghidra tried to read and write under the user’s real tree, which is not allowed in this sandbox.

The web agent’s contribution here was practical rather than semantic. It suggested:

* redirecting Ghidra’s settings and “home” to repo-local paths using `JAVA_TOOL_OPTIONS` and environment variables, e.g.:
  * `-Dapplication.settingsdir=$PWD/.ghidra-user`,
  * `-Duser.home=$PWD/dumps/ghidra/user`,
* seeding a local `java_home.save` under that settings directory so headless would not prompt,
* and avoiding unsupported flags, wiring `JAVA_HOME` and `-vmPath` consistently through the repo’s `book/api/ghidra` helpers.

Once the codex agent adopted the same pattern used by the `ghidra` scaffolding in the repo, headless runs stabilized and scripts for the sandbox kext (including the `find_field2_evaluator` and caller-dump passes) could run without interactive prompts.

With static inventories in hand and Ghidra available, the web agent steered the kernel-side work toward two questions:

1. **Is there any evidence that the kernel splits `filter_arg_raw` into hi/lo bitfields using 0x3fff/0x4000 or similar masks?**
2. **Is there any direct comparison or table index that uses the high constants seen in the graphs (16660, 2560, 10752, 0xffff, 3584)?**

The codex agent’s runs, summarized in `book/experiments/field2-filters/Report.md` and in `troubles/field2-hunting.md`, answered both negatively for this host:

* It carved `com.apple.security.sandbox` from the arm64e kernel cache and, using the `find_field2_evaluator` scripts, located:
  * `__read16` at `fffffe000b40fa1c` as the u16 reader: bounds checks on the profile stream, then a plain `ldrh`, no masking or bit tests; the value is forwarded as-is.
  * `_eval` at `fffffe000b40d698` as the main PolicyGraph evaluator: a bytecode-style VM over the profile blob that:
    * reads an opcode/tag byte,
    * bounds-checks a cursor against profile limits,
    * dispatches via a tag-based switch, and
    * uses masks like 0x7f / 0xffffff / 0x7fffff for other operand fields, but never 0x3fff/0x4000/0xc000 on the u16 payload.
* A separate caller dump for `__read16` (stored under `dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/read16_callers.txt`) showed:
  * callers such as `_check_syscall_mask_composable`, `_iterate_sandbox_state_flags`, `_match_network`, `_variables_populate`, `__readstr`, `__readaddr`,
  * occasional `tst`/`and` with `#0xffff` to mask the payload back to 16 bits for range or index checks,
  * but no immediates matching the high constants from the graphs.

In parallel, a separate “node struct” search (`kernel_node_struct_scan.py`) walked all functions reachable from `_eval` looking for a fixed-stride `[byte + ≥2×u16]` layout that would match the classic Blazakis-style node array:

* The scan returned no viable candidates in the sandbox kext for this Sonoma host; only a couple of noisy hits in non-sandbox code.
* That negative result is recorded in `dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/node_struct_scan.{txt,json}` and reflects what `Report.md` calls a “VM-style evaluator over a profile blob,” not a direct indexed node array.

Taken together, the kernel-side evidence strongly supports the experiment’s bottom line: on this host, the kernel reads `filter_arg_raw` as a plain u16, applies generic `#0xffff` masking in some helpers, and does not visibly implement a hi/lo split using 0x3fff/0x4000. Whatever semantics drive the high values are implemented in helper logic we have not yet tied to specific constants, not in a simple bitfield scheme.

---

By the end of the `field2-filters` experiment, the web agent’s role was largely to help the human and codex agents recognize that they had, in fact, reached the edge of what this host could tell them with their current tools:

* Static inventories (`field2_inventory.json`, `unknown_nodes.json`) pinned down where the interesting high values live:
  * a shared `bsd` tail (16660) reachable from ops 0–27,
  * airlock’s cluster (165/166/10752 plus a 0xffff sentinel) around `system-fcntl`,
  * a flow-divert branch (2560) only in mixed require-all socket probes,
  * and a small `sample` sentinel (3584) used as an op-empty branch.
* Tag layouts and op reach from `unknown_nodes.json` gave each unknown a clear structural profile (tag, fan-in/fan-out, successor layout) without revealing semantics.
* Kernel work showed:
  * no 0x3fff/0x4000-style splitting of the payload,
  * no direct comparisons against the high constants,
  * and no recoverable node struct inside the kext for this Sonoma build.

The web agent’s final recommendation, which matches the closure language now in `Report.md` and `troubles/field2-hunting.md`, was to mark this line of inquiry as **complete (negative)** for this host:

* We know that low `field2` IDs are just filter vocab IDs.
* We know exactly where the remaining high values appear, and how they sit in the graphs.
* We know the kernel treats `filter_arg_raw` as a u16 with no obvious hi/lo mask.
* We do **not** know the semantics of the high values themselves.

Any further progress will require **new work**, not more mining of the same artifacts—most likely:

* targeted analysis of how specific helpers (like `_match_network` or syscall-mask helpers) use the payload as an index or key, or
* a userland `libsandbox` compiler study that correlates SBPL filters and payloads directly at compile time.

The web agent thus helped the pair-programming session stop at an honest boundary: `field2-filters` and `Field2 hunting` are closed on this host, with unknowns bounded but unmapped, and any future work will spin up as new experiments that treat these notes as fixed context.
