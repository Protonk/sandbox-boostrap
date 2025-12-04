# Zero knowledge macOS Reverse Engineering 
> Validating policy graphs from scratch through pair programming

This report describes what happened when we asked two cooperating AI agents to answer a very specific question about a modern system: what a particular “third field” in its internal rules actually does. Older systems were often modeled as simple tables of rules, each with a type, two “next rule” pointers, and a small integer payload that tweaked behavior. The natural idea was to reuse that model: search for those tables, analyze the payloads and strides, and infer structure. We suspected that this might no longer hold on current systems, but until we checked, that was just an educated guess.

To investigate, we split the work between two agents. One had web access and broad background knowledge; it knew the public papers and folklore, and could propose strategies, pitfalls, and stopping rules. The other had no web access at all, but could see the actual project, the decoded rule graphs, and the disassembled binaries from a single real machine. That “codex” agent wrote and ran scripts, scanned the binaries, and analyzed the graphs, then reported findings back. The human role was mostly to define the question, wire up the environment, and let this loop run.

Together, the agents tried every straightforward explanation for the strange values in that third field. They checked whether those values were just unknown rule IDs, table indices, or literal encodings. They looked for the old pattern of “row of structs” in memory and for bit-level tricks—masks that split the field into flags and indices, or comparisons against special constants. On this system, all those paths came back negative: low values behaved like normal rule IDs, high values appeared only in a few tightly constrained places, and the verifier treated the field as an undistinguished 16-bit number. The interesting values remain unexplained, but they are now tightly bounded and clearly *not* explained by the old stories.

The most important outcome is that this experiment, and this report, now stand as a sentinel for future agent-led runs. They don’t just say “we think the old method doesn’t work”; they encode the scripts, logs, and reasoning that show why, on this kind of system, table-and-stride analysis and simple bitfield guessing are dead ends. That means future agents can treat this result as a guardrail: they can rely on its conclusions, adopt its environment setup and tooling, and focus their creativity on genuinely new directions (different subsystems, dynamic behavior, userland compilers) rather than circling the same cul-de-sac. The example itself becomes part of the system’s memory of “how to investigate,” not just a one-off answer about a single field.

## Report

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

Given Blazakis-era layouts, the natural instinct was to treat `field2` as `filter_arg`, assume a struct like `[byte tag, byte filter, u16 arg, u16 edge0, u16 edge1]`, and go hunting for that pattern in the kernel: fixed stride arrays, base+index addressing, hi/lo bitfields for flags. The initial suspicion was that Sonoma’s kernel might have moved past that simple representation, but this was only a suspicion; nothing in the codebase or public sources had yet forced the issue, and those older layouts were treated—as `substrate/Canon.md` explicitly insists—as hypotheses to test, not as ground truth for this host.

### Bringing the web agent into the loop

At that point, the web agent was pulled in explicitly and given a project-local definition of `field2`. With that anchored, its role was:

* To tie `field2` back to the canonical `filter_arg` concept from earlier reversing work.
* To check public sources for any Sonoma- or Ventura-era documentation about new node formats, flag bits, or mappings of high `filter_arg` values.
* To suggest next steps that respected both the project’s invariants and the limits of public knowledge.

The web agent confirmed that public work still describes the third 16-bit slot as “filter-specific payload/argument,” and nothing more; there is no published mapping from specific high values like 0x0a00 or 0x4114 to concrete filters. It is entirely compatible with public descriptions that:

* there are internal filters and predicates not exposed in SBPL or libsandbox strings, and
* those internal filters may encode extra semantics in the argument bits,

but the details are not written down. On this host, the “mystery” values are a small, fixed set—0x4114, 0x0a00, 0x2a00, 0xe00, 0xffff and the mid-range IDs 165/166/170/174/115/109—that only appear in the curated system blobs and a handful of probes, and the web agent’s role was to frame them, not to name their semantics.

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

First, the environment had to be made workable. Headless [Ghidra](../../book/api/ghidra/README.md) runs were blocked by the usual JDK selection prompt and writes under the real `$HOME`. The web agent explained how Ghidra locates its settings directory and `java_home.save` cache, and suggested redirecting both to repo-local paths; the codex agent implemented that pattern so `analyzeHeadless` could run against the BootKernelCollection and reuse an existing project without interactive prompts. That setup became reusable infrastructure for everything that followed and is now the standard recipe for kernel tasks under `dumps/ghidra/out/14.4.1-23E224`.

Second, the codex agent built and used a small family of Ghidra scripts:

* [to find and dump callers](../../book/api/ghidra/scripts/find_field2_evaluator.py) of the 16-bit reader (`__read16`),
* to locate the main evaluator (`_eval`) and sketch its control structure, and
* [to search for “node-like” fixed-stride structs](../../book/api/ghidra/scripts/kernel_node_struct_scan.py) under `_eval` and more broadly in the sandbox kext.

At each stage, the web agent read the summaries, connected them back to the conceptual model, and steered the next small step.

The codex agent’s findings can be summarized at this level:

* `__read16` really is a plain u16 read from the profile stream, with callers sometimes masking back to 0xffff but never testing for the high `field2` constants directly.
* `_eval` is a central evaluator, but it presents as a bytecode VM: it reads a tag/opcode byte from `[profile_base + cursor]`, checks bounds, dispatches via a jump table, and lets helpers interpret operands; one arm uses a 24-bit immediate masked with 0xffffff.
* No 0x3fff/0x4000/0xc000 masks or high-constant compares show up in `_eval` or the immediate operand-decode helpers.

Those helper and evaluator entrypoints are recorded verbatim in `field2_evaluator.json`, so later experiments can relocate them without repeating the whole search.

To chase the hoped-for Blazakis-style struct representation, the codex agent then developed more systematic structure scans:

* a script to identify functions that do “base + scaled index” followed by loads from `base + offset`, and
* a constrained scan for cases where those loads look like “one byte + multiple halfwords” from a fixed stride, under functions reachable from `_eval`.

Those scans, built from the web agent’s high-level patterns, were aimed squarely at discovering an in-kernel array of `[tag, filter, edge0, edge1, payload]` nodes.

### Exhausting the obvious explanations

In parallel with the kernel work, the decoded graphs were being combed for patterns that might suggest an alternate explanation for high `field2` values: literal or regex indices, parameter tables, or graph-level metafilters. Those hypotheses were systematically knocked down, and each closed path was reflected back into the inventories and notes rather than left as a vague impression:

* high values did not match literal table indices, offsets, or any simple linear transformation thereof;
* their presence was tightly tied to rich, mixed profiles (e.g., require-all network + flow-divert) studied in the [probe-op-structure experiment](../../book/experiments/probe-op-structure/Report.md) and to specific tails, not scattered randomly; and
* small synthetic SBPL fragments built around the interesting literals (flow-divert, `/dev/dtracehelper`, etc.) in the [`field2-filters` probes](../../book/experiments/field2-filters/sb/) collapsed back to low IDs, suggesting context-sensitivity in the compiler or emitter rather than an obvious “use this filter ID when you see this literal” mapping.

On the kernel side, the sequence of hypotheses and results went roughly as follows:

* If the kernel were splitting `filter_arg_raw` into hi/lo bits using masks like 0x3fff/0x4000, we would expect to see those masks in the evaluator; none appeared, and masking was uniformly 0xffff, just preserving the u16 range.
* If high `field2` values were being singled out as magic constants, we would expect to see immediate values like 0x0a00, 0x4114, 0x2a00, 0xffff in sandbox kext code; immediate scans and focused disassembly around `_eval` and its helpers did not.
* If the kernel still had an in-memory node array matching the decoded layout, we would expect to find functions that do `base + (index * stride)` and then read a byte and two halfwords from small offsets; dedicated struct scans over the sandbox kext functions reachable from `_eval` reported no convincing instances.

Each of these avenues was explored with scripts, recorded outputs, and concrete addresses; each came back negative for this host, including multiple passes of `kernel_field2_mask_scan`, `kernel_imm_search`, and `kernel_node_struct_scan.py` over the sandbox kext slice for build 23E224. By the end of the run, the combination of:

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
* It leaves behind improved tooling and wiring: more reliable headless Ghidra on this host, reusable scan scripts, and schema-tagged outputs that can be fed into later experiments. In practice this means the `book/api/ghidra` scaffold, the `find_field2_evaluator` and `kernel_node_struct_scan` tasks, and their outputs under `dumps/ghidra/out/14.4.1-23E224/` now serve as the common entrypoint for any kernel/evaluator work the textbook needs, not just this one trouble.

The jumping-off points are therefore fairly crisp: if the project wants to learn more about high `field2` values, it can design a new experiment that either:

* traces how particular profile regions and tags are evaluated by specific helper functions, looking for argument-dependent behaviour, or
* inspects `libsandbox` to see how it encodes filter arguments and whether any internal filter kinds line up with the high codes surfaced here.

Either way, the current experiment’s job is done; its role is to be a fixed backdrop, not an open thread.

## On structured agent pairing

This result depended on a deliberate split between a web-facing agent and a repo-local codex agent. The web agent never touched the Sonoma host or its artifacts; its job was to keep the historical picture of Seatbelt in view, propose lines of attack, and set stopping rules that respected the project’s invariants. The codex agent, in turn, stayed inside this repo and machine, turning those proposals into concrete scripts, experiment runs, and Ghidra tasks against the fixed Sonoma baseline.

That division of labour mattered because the main outcome was “no, but not in the way we expected.” Suspicions about hi/lo flags and node arrays are easy to form and hard to retire; having one agent hold the conceptual map and another produce the inventories, dumps, and scans made it easier to decide when a hypothesis had really been exhausted for this host. When both views aligned on “VM-style evaluator, raw u16 payload, high values still unmapped,” the project gained a stable negative result with a clear trail back to the work that produced it—and a concrete example of how to structure similar “zero knowledge” runs in the future.

## Conclusion

Our outcome is that on this host, the third node slot is best described as `filter_arg_raw`: a plain u16 payload whose high values are rare, structurally bounded, and still semantically unmapped, with new tooling in place to keep future work grounded. We also learned the web agent <-> codex agent loop works even when web search is exhausted. We quickly moved past what exists in published work returned in the model's search: the benefits of a partner did not drop. This suggests that the value is not only in the web search, but in dyadic exchange.

Beyond that, this work nudges the project into better long-term habits: it treats negative results as first-class artifacts rather than private hunches, reinforces the practice of threading validation status and inventories into every claim, and exercises the shared Ghidra and decoder APIs in a way that will make future experiments easier to compare and audit. Even if `field2` itself remains only partially understood, the investigation tightened the feedback loop between substrate concepts, mapping datasets, and reverse-engineering tools on this host.

The above benefits sound airy and ethereal. They are, in a sense. The quality of work and the speed of the loop in agentic coding is bound up in the richness and clarity of examples showing paths for agents to follow. A "nudge" for agents is an example of best practices, one they will take seriously, but only probalistically. This is the first. The rest will be easier. 
