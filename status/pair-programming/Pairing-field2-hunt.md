This report follows the [`field2` investigation](../../book/experiments/field2-filters/Report.md) on macOS 14.4.1, tracing how an initial suspicion that older node-layout heuristics might not scale turned into a structured web–codex pairing over static graphs and kernel artifacts. It documents how that collaboration converged on a bounded negative result—`filter_arg_raw` is a plain u16 payload whose high values are structurally understood but still unmapped—and the concrete experiments, tooling, and guardrails that now anchor any future `field2` work on this host.

## Report

The investigation began with a small but stubborn set of high `field2` values in otherwise well-understood system profiles, prompting a focused pass over decoded graphs and synthetic probes to see whether these numbers could be tied to known Filters or literal indices. That phase produced stable inventories and unknown-node tables, clarified where each interesting value lives in the PolicyGraphs, and showed that low `field2` values line up cleanly with the canonical filter vocabulary while the highs remain sparse and profile-specific.

From there, the work moved into the kernel: pairing Ghidra-based searches and helper/evaluator scripts with the static view of profiles to test concrete hypotheses about hi/lo bit usage and in-memory node layouts. Those scans located the evaluator and its u16 reader, ruled out any visible 0x3fff/0x4000-style bit splits or magic-constant compares for the high values, and found no evidence of a Blazakis-style node array reachable from `_eval`, reinforcing the view that `filter_arg_raw` is consumed as a plain 16-bit payload in a VM-like evaluator.

The result is a deliberately negative but useful closure: the `field2` slot is now treated as `filter_arg_raw`, with all known high values structurally bounded but semantically unmapped, and further progress explicitly deferred to new experiments that must build on these artifacts rather than repeat earlier guesses. Along the way, the pairing left behind reusable tooling (Ghidra scaffolding, node-struct scanners, profile inventories) and guardrails that prevent future work on this host from silently reintroducing disproven assumptions about hi/lo flags or simple node structs.

### Background and early suspicion

The project’s [decoded policy graphs](../../book/experiments/node-layout/Report.md) expose a familiar shape for each node: two edge pointers and a third 16-bit payload, dubbed `field2`. For most nodes on this Sonoma host, `field2` lines up cleanly with the harvested filter vocabulary: path, mount-relative-path, global/local name, socket-type, iokit filters, and so on. System profiles ([airlock, bsd, sample](../../book/experiments/system-profile-digest/Report.md)) reinforce those mappings, and their low `field2` values land directly on the 93-entry filter table in `book/graph/mappings/vocab/filters.json`.

But a small set of nodes in richer profiles do something else entirely. In the bsd profile, the tail region carries high `field2` codes like 16660 and nearby 170/174/115/109; in airlock, there are clusters around 165/166/10752 and a 0xffff sentinel; in flow-divert mixed profiles, a `com.apple.flow-divert` branch carries 2560 that disappears as soon as the profile is simplified. These values don’t match the known filter IDs, literal indices, or obvious derived indices.

For example, the inventory records the `bsd` tail node like this:

```json
{
  "idx": 27,
  "tag": 0,
  "fields": [0, 3840, 16660, 26, 27],
  "raw": 16660,
  "raw_hex": "0x4114",
  "hi": 16384,
  "lo": 276,
  "literal_refs": [
    "\n[appleinternal/lib/sanitizers",
    "\n`share/posix_spawn_filtering_rules",
    "P/dev/dtracehelper"
  ]
}
```

Given Blazakis-era layouts, the natural instinct was to treat `field2` as `filter_arg`, assume a struct like `[byte tag, byte filter, u16 arg, u16 edge0, u16 edge1]`, and go hunting for that pattern in the kernel: fixed stride arrays, base+index addressing, hi/lo bitfields for flags. The initial suspicion was that Sonoma’s kernel might have moved past that simple representation, but this was only a suspicion; nothing in the codebase or public sources had yet forced the issue.

### Bringing the web agent into the loop

At that point, the web agent was pulled in explicitly and given a project-local definition of `field2`. With that anchored, its role was:

* To tie `field2` back to the canonical `filter_arg` concept from earlier reversing work.
* To check public sources for any Sonoma- or Ventura-era documentation about new node formats, flag bits, or mappings of high `filter_arg` values.
* To suggest next steps that respected both the project’s invariants and the limits of public knowledge.

The web agent confirmed that public work still describes the third 16-bit slot as “filter-specific payload/argument,” and nothing more; there is no published mapping from specific high values like 0x0a00 or 0x4114 to concrete filters. It is entirely compatible with public descriptions that:

* there are internal filters and predicates not exposed in SBPL or libsandbox strings, and
* those internal filters may encode extra semantics in the argument bits,

but the details are not written down. On this host, the “mystery” values are a small, fixed set—0x4114, 0x0a00, 0x2a00, 0xe00, 0xffff and the mid-range IDs 165/166/170/174/115/109—that only appear in the curated system blobs and a handful of probes.

Given that, the web agent recommended:

* treating `field2` explicitly as `filter_arg_raw` and exposing hi/lo views (`raw & 0xc000`, `raw & 0x3fff`) as *analytic tools*, not assumed kernel behaviour;
* leaning on graph structure (tags, fan-in/fan-out, op reachability) to understand where the high values live; and
* using kernel evidence, not guesswork, to determine whether those bits are ever split or tested.

This is exactly how the field2 inventory code computes and records those views:

```python
raw = fields[2]
hi = raw & 0xC000
lo = raw & 0x3FFF
entry = hist.setdefault(
    raw,
    {
        "raw": raw,
        "raw_hex": hex(raw),
        "hi": hi,
        "lo": lo,
        "name": filter_names.get(lo) if hi == 0 else None,
        "count": 0,
        "tags": {},
    },
)
```

This is the exact split the inventories use when they talk about `hi` and `lo` for `filter_arg_raw`.

That set the frame for the codex agent: we’re not looking for “mystery third field semantics” in the abstract, we’re asking “what does the kernel actually do with the u16 argument it reads from the profile?”

### Web–codex interaction pattern

From there, the human user largely stepped out, and the interaction became a structured loop between:

* the web agent, proposing strategies grounded in public Seatbelt knowledge and general reverse-engineering practice, and
* the codex agent, running concrete scripts against the repo, kernelcaches, and decoded graphs on the Sonoma host, then reporting back.

There were a few distinct phases.

First, the environment had to be made workable. Headless [Ghidra](../../book/api/ghidra/README.md) runs were blocked by the usual JDK selection prompt and writes under the real `$HOME`. The web agent explained how Ghidra locates its settings directory and `java_home.save` cache, and suggested redirecting both to repo-local paths via JVM properties and environment variables, then seeding a local `java_home.save`. The codex agent implemented that pattern; once in place, `analyzeHeadless` could run against the BootKernelCollection and reuse an existing project without any interactive prompts. That setup became reusable infrastructure for everything that followed and is now the standard recipe for kernel tasks under `dumps/ghidra/out/14.4.1-23E224`.

Second, the codex agent built and used a small family of Ghidra scripts:

* [to find and dump callers](../../book/api/ghidra/scripts/find_field2_evaluator.py) of the 16-bit reader (`__read16`),
* to locate the main evaluator (`_eval`) and sketch its control structure, and
* [to search for “node-like” fixed-stride structs](../../book/api/ghidra/scripts/kernel_node_struct_scan.py) under `_eval` and more broadly in the sandbox kext.

At each stage, the web agent read the summaries, connected them back to the conceptual model, and steered the next small step.

The codex agent’s findings can be summarized at this level:

* `__read16` really is a plain u16 read from the profile stream, with callers sometimes masking back to 0xffff but never testing for the high `field2` constants directly.
* `_eval` is a central evaluator, but it presents as a bytecode VM: it reads a tag/opcode byte from `[profile_base + cursor]`, checks bounds, dispatches via a jump table, and lets helpers interpret operands; one arm uses a 24-bit immediate with masks like 0xffffff and 0x7fffff.
* No 0x3fff/0x4000/0xc000 masks or high-constant compares show up in `_eval` or the immediate operand-decode helpers.

Those helper and evaluator entrypoints are recorded verbatim in `field2_evaluator.json`, so later experiments can relocate them without repeating the whole search.

To chase the hoped-for Blazakis-style struct representation, the codex agent then developed more systematic structure scans:

* a script to identify functions that do “base + scaled index” followed by loads from `base + offset`, and
* a constrained scan for cases where those loads look like “one byte + multiple halfwords” from a fixed stride, under functions reachable from `_eval`.

Those scans, built from the web agent’s high-level patterns, were aimed squarely at discovering an in-kernel array of `[tag, filter, edge0, edge1, payload]` nodes.

### Exhausting the obvious explanations

In parallel with the kernel work, the decoded graphs were being combed for patterns that might suggest an alternate explanation for high `field2` values: literal or regex indices, parameter tables, or graph-level metafilters. Those hypotheses were systematically knocked down:

* high values did not match literal table indices, offsets, or any simple linear transformation thereof;
* their presence was tightly tied to rich, mixed profiles (e.g., require-all network + flow-divert) studied in the [probe-op-structure experiment](../../book/experiments/probe-op-structure/Report.md) and to specific tails, not scattered randomly; and
* small synthetic SBPL fragments built around the interesting literals (flow-divert, `/dev/dtracehelper`, etc.) in the [`field2-filters` probes](../../book/experiments/field2-filters/sb/) collapsed back to low IDs, suggesting context-sensitivity in the compiler or emitter rather than an obvious “use this filter ID when you see this literal” mapping.

On the kernel side, the sequence of hypotheses and results went roughly as follows:

* If the kernel were splitting `filter_arg_raw` into hi/lo bits using masks like 0x3fff/0x4000, we would expect to see those masks (or equivalent bit tests) in the evaluator. The codex agent’s searches turned up none; masking was uniformly 0xffff, just preserving the u16 range.
* If high `field2` values were being singled out as magic constants, we would expect to see immediate values like 0x0a00, 0x4114, 0x2a00, 0xffff showing up in sandbox kext code. Immediate scans and focused disassembly around `_eval` and its helpers did not reveal any such comparands.
* If the kernel still had an in-memory node array matching the decoded layout, we would expect to find functions that do `base + (index * stride)` and then read a byte and two halfwords from small offsets. The dedicated struct scans, restricted to the sandbox kext and functions reachable from `_eval`, reported no convincing instances of that pattern.

Each of these avenues was explored with scripts, recorded outputs, and concrete addresses; each came back negative for this host. In practice that meant multiple passes of `kernel_field2_mask_scan`, `kernel_imm_search`, and `kernel_node_struct_scan.py` over the sandbox kext slice for build 23E224. By the end of the run, the combination of:

* public knowledge about how the historical format behaved,
* [decoded graph inventories](../../book/experiments/field2-filters/out/field2_inventory.json) and [unknown-node tables](../../book/experiments/field2-filters/out/unknown_nodes.json), and
* kernel-side scanning results

left very little room for the idea that the Sonoma kernel was quietly implementing a simple hi/lo bitfield split or using a Blazakis-style node array behind the scenes. The more coherent picture was: the kernel is interpreting a VM-ish profile representation, takes `filter_arg_raw` as a plain u16 payload, and any semantics for high values are encoded in helper logic that has not yet been correlated with the decoded graphs.

### Closure, gains, and where to go next

By the end of the thread, the `field2` experiment had a clear, bounded outcome for this host:

* The third 16-bit slot in decoded graphs is still best described as `filter_arg_raw`: a per-node argument whose meaning depends on the filter.
* Low values are mapped: they line up with the system’s filter vocabulary and behave as expected across profiles.
* High values are localized and structurally understood (bsd’s shared tail, airlock’s system-fcntl cluster, flow-divert’s mixed-profile branch, a small sample sentinel), but their semantics remain unknown.
* The kernel reads and masks this argument as a u16 and does not visibly implement a hi/lo split or treat those specific high values as magic constants.
* There is no simple, recoverable `[tag, filter, edge0, edge1, payload]` struct array living under `_eval` on 14.4.1.

The unknown high values remain in the inventories as explicit `UnknownFilterArg(raw)` entries rather than being merged into the known filter vocabulary.

The important part is not that some ideas were ruled out; it’s that they are now ruled out *with artifacts*. There are inventories showing where every interesting `field2` value lives, [caller dumps and layouts](../../dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/field2_evaluator.json) for the key kernel functions, [node-struct scans](../../dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/node_struct_scan.json) with explicit search criteria and zero matches, and [experiment docs](../../troubles/field2-hunting.md) that tie these pieces together and mark the status as “closed (negative)” for this substrate.

That closure has several concrete advantages:

* It prevents future agents or contributors from silently re-running the same “maybe there’s a node array / hi-bit flag” lines of attack every time `field2` comes up.
* It clarifies that further progress on `field2` mapping will require genuinely new work—dynamic analysis of specific helpers, or a userland `libsandbox` compiler study—rather than more fine-grained heuristics over the same KC.
* It leaves behind improved tooling and wiring: reliable headless Ghidra on this host, reusable scan scripts, and schema-tagged outputs that can be fed into later experiments. In practice this means the `book/api/ghidra` scaffold, the `find_field2_evaluator` and `kernel_node_struct_scan` tasks, and their outputs under `dumps/ghidra/out/14.4.1-23E224/` now serve as the common entrypoint for any kernel/evaluator work the textbook needs, not just this one trouble.

The jumping-off points are therefore fairly crisp: if the project wants to learn more about high `field2` values, it can design a new experiment that either:

* traces how particular profile regions and tags are evaluated by specific helper functions, looking for argument-dependent behaviour, or
* inspects `libsandbox` to see how it encodes filter arguments and whether any internal filter kinds line up with the high codes surfaced here.

Either way, the current experiment’s job is done; its role is to be a fixed backdrop, not an open thread.

## On structured agent pairing

This result depended on a deliberate split between a web-facing agent and a repo-local codex agent. The web agent never touched the Sonoma host or its artifacts; its job was to keep the historical picture of Seatbelt in view, propose lines of attack, and set stopping rules that respected the project’s invariants. The codex agent, in turn, stayed inside this repo and machine, turning those proposals into concrete scripts, experiment runs, and Ghidra tasks. Critically, this loop did not require expert guidance by a human, merely situated action.

That division of labour mattered because the main outcome was “no, but not in the way we expected.” Suspicions about hi/lo flags and node arrays are easy to form and hard to retire; having one agent hold the conceptual map and another produce the inventories, dumps, and scans made it easier to decide when a hypothesis had really been exhausted for this host. When both views aligned on “VM-style evaluator, raw u16 payload, high values still unmapped,” the project gained a stable negative result with a clear trail back to the work that produced it. 
