This report captures the arc of the [`field2` investigation](../../book/experiments/field2-filters/Report.md) on macOS 14.4.1: from early suspicion that the old 2011-era tricks wouldn’t scale, through a coordinated web–codex loop, to a clear negative conclusion and a set of concrete gains.

---

### Background and early suspicion

The project’s [decoded policy graphs](../../book/experiments/node-layout/Report.md) expose a familiar shape for each node: two edge pointers and a third 16-bit payload, dubbed `field2`. For most nodes on this Sonoma host, `field2` lines up cleanly with the harvested filter vocabulary: path, mount-relative-path, global/local name, socket-type, iokit filters, and so on. System profiles reinforce those mappings.

But a small set of nodes in richer profiles do something else entirely. In the bsd profile, the tail region carries high `field2` codes like 16660 and nearby 170/174/115/109; in airlock, there are clusters around 165/166/10752 and a 0xffff sentinel; in flow-divert mixed profiles, a `com.apple.flow-divert` branch carries 2560 that disappears as soon as the profile is simplified. These values don’t match the known filter IDs, literal indices, or obvious derived indices.

Given Blazakis-era layouts, the natural instinct was to treat `field2` as `filter_arg`, assume a struct like `[byte tag, byte filter, u16 arg, u16 edge0, u16 edge1]`, and go hunting for that pattern in the kernel: fixed stride arrays, base+index addressing, hi/lo bitfields for flags. The initial suspicion was that Sonoma’s kernel might have moved past that simple representation, but this was only a suspicion; nothing in the codebase or public sources had yet forced the issue.

---

### Bringing the web agent into the loop

At that point, the web agent was pulled in explicitly and given a project-local definition of `field2`. With that anchored, its role was:

* To tie `field2` back to the canonical `filter_arg` concept from earlier reversing work.
* To check public sources for any Sonoma- or Ventura-era documentation about new node formats, flag bits, or mappings of high `filter_arg` values.
* To suggest next steps that respected both the project’s invariants and the limits of public knowledge.

The web agent confirmed that public work still describes the third 16-bit slot as “filter-specific payload/argument,” and nothing more; there is no published mapping from specific high values like 0x0a00 or 0x4114 to concrete filters. It is entirely compatible with public descriptions that:

* there are internal filters and predicates not exposed in SBPL or libsandbox strings, and
* those internal filters may encode extra semantics in the argument bits,

but the details are not written down.

Given that, the web agent recommended:

* treating `field2` explicitly as `filter_arg_raw` and exposing hi/lo views (`raw & 0xc000`, `raw & 0x3fff`) as *analytic tools*, not assumed kernel behaviour;
* leaning on graph structure (tags, fan-in/fan-out, op reachability) to understand where the high values live; and
* using kernel evidence, not guesswork, to determine whether those bits are ever split or tested.

That set the frame for the codex agent: we’re not looking for “mystery third field semantics” in the abstract, we’re asking “what does the kernel actually do with the u16 argument it reads from the profile?”

---

### Web–codex interaction pattern

From there, the human user largely stepped out, and the interaction became a structured loop between:

* the web agent, proposing strategies grounded in public Seatbelt knowledge and general reverse-engineering practice, and
* the codex agent, running concrete scripts against the repo, kernelcaches, and decoded graphs on the Sonoma host, then reporting back.

There were a few distinct phases.

First, the environment had to be made workable. Headless [Ghidra](../../book/api/ghidra/README.md) runs were blocked by the usual JDK selection prompt and writes under the real `$HOME`. The web agent explained how Ghidra locates its settings directory and `java_home.save` cache, and suggested redirecting both to repo-local paths via JVM properties and environment variables, then seeding a local `java_home.save`. The codex agent implemented that pattern; once in place, `analyzeHeadless` could run against the BootKernelCollection and reuse an existing project without any interactive prompts. That setup became reusable infrastructure for everything that followed.

Second, the codex agent built and used a small family of Ghidra scripts:

* [to find and dump callers](../../book/api/ghidra/scripts/find_field2_evaluator.py) of the 16-bit reader (`__read16`),
* to locate the main evaluator (`_eval`) and sketch its control structure, and
* [to search for “node-like” fixed-stride structs](../../book/api/ghidra/scripts/kernel_node_struct_scan.py) under `_eval` and more broadly in the sandbox kext.

At each stage, the web agent read the summaries, connected them back to the conceptual model, and steered the next small step.

The codex agent’s findings can be summarized at this level:

* `__read16` really is a plain u16 read from the profile stream, with callers sometimes masking back to 0xffff but never testing for the high `field2` constants directly.
* `_eval` is a central evaluator, but it presents as a bytecode VM: it reads a tag/opcode byte from `[profile_base + cursor]`, checks bounds, dispatches via a jump table, and lets helpers interpret operands; one arm uses a 24-bit immediate with masks like 0xffffff and 0x7fffff.
* No 0x3fff/0x4000/0xc000 masks or high-constant compares show up in `_eval` or the immediate operand-decode helpers.

To chase the hoped-for Blazakis-style struct representation, the codex agent then developed more systematic structure scans:

* a script to identify functions that do “base + scaled index” followed by loads from `base + offset`, and
* a constrained scan for cases where those loads look like “one byte + multiple halfwords” from a fixed stride, under functions reachable from `_eval`.

Those scans, built from the web agent’s high-level patterns, were aimed squarely at discovering an in-kernel array of `[tag, filter, edge0, edge1, payload]` nodes.

---

### Exhausting the obvious explanations

In parallel with the kernel work, the decoded graphs were being combed for patterns that might suggest an alternate explanation for high `field2` values: literal or regex indices, parameter tables, or graph-level metafilters. Those hypotheses were systematically knocked down:

* high values did not match literal table indices, offsets, or any simple linear transformation thereof;
* their presence was tightly tied to rich, mixed profiles (e.g., require-all network + flow-divert) and to specific tails, not scattered randomly; and
* small synthetic SBPL fragments built around the interesting literals (flow-divert, `/dev/dtracehelper`, etc.) collapsed back to low IDs, suggesting context-sensitivity in the compiler or emitter rather than an obvious “use this filter ID when you see this literal” mapping.

On the kernel side, the sequence of hypotheses and results went roughly as follows:

* If the kernel were splitting `filter_arg_raw` into hi/lo bits using masks like 0x3fff/0x4000, we would expect to see those masks (or equivalent bit tests) in the evaluator. The codex agent’s searches turned up none; masking was uniformly 0xffff, just preserving the u16 range.
* If high `field2` values were being singled out as magic constants, we would expect to see immediate values like 0x0a00, 0x4114, 0x2a00, 0xffff showing up in sandbox kext code. Immediate scans and focused disassembly around `_eval` and its helpers did not reveal any such comparands.
* If the kernel still had an in-memory node array matching the decoded layout, we would expect to find functions that do `base + (index * stride)` and then read a byte and two halfwords from small offsets. The dedicated struct scans, restricted to the sandbox kext and functions reachable from `_eval`, reported no convincing instances of that pattern.

Each of these avenues was explored with scripts, recorded outputs, and concrete addresses; each came back negative for this host. By the end of the run, the combination of:

* public knowledge about how the historical format behaved,
* [decoded graph inventories](../../book/experiments/field2-filters/out/field2_inventory.json) and [unknown-node tables](../../book/experiments/field2-filters/out/unknown_nodes.json), and
* kernel-side scanning results

left very little room for the idea that the Sonoma kernel was quietly implementing a simple hi/lo bitfield split or using a Blazakis-style node array behind the scenes. The more coherent picture was: the kernel is interpreting a VM-ish profile representation, takes `filter_arg_raw` as a plain u16 payload, and any semantics for high values are encoded in helper logic that has not yet been correlated with the decoded graphs.

---

### Closure, gains, and where to go next

By the end of the thread, the `field2` experiment had a clear, bounded outcome for this host:

* The third 16-bit slot in decoded graphs is still best described as `filter_arg_raw`: a per-node argument whose meaning depends on the filter.
* Low values are mapped: they line up with the system’s filter vocabulary and behave as expected across profiles.
* High values are localized and structurally understood (bsd’s shared tail, airlock’s system-fcntl cluster, flow-divert’s mixed-profile branch, a small sample sentinel), but their semantics remain unknown.
* The kernel reads and masks this argument as a u16 and does not visibly implement a hi/lo split or treat those specific high values as magic constants.
* There is no simple, recoverable `[tag, filter, edge0, edge1, payload]` struct array living under `_eval` on 14.4.1.

The important part is not that some ideas were ruled out; it’s that they are now ruled out *with artifacts*. There are inventories showing where every interesting `field2` value lives, [caller dumps and layouts](../../dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/field2_evaluator.json) for the key kernel functions, [node-struct scans](../../dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/node_struct_scan.json) with explicit search criteria and zero matches, and [experiment docs](../../troubles/field2-hunting.md) that tie these pieces together and mark the status as “closed (negative)” for this substrate.

That closure has several concrete advantages:

* It prevents future agents or contributors from silently re-running the same “maybe there’s a node array / hi-bit flag” lines of attack every time `field2` comes up.
* It clarifies that further progress on `field2` mapping will require genuinely new work—dynamic analysis of specific helpers, or a userland `libsandbox` compiler study—rather than more fine-grained heuristics over the same KC.
* It leaves behind improved tooling and wiring: reliable headless Ghidra on this host, reusable scan scripts, and schema-tagged outputs that can be fed into later experiments.

The jumping-off points are therefore fairly crisp: if the project wants to learn more about high `field2` values, it can design a new experiment that either:

* traces how particular profile regions and tags are evaluated by specific helper functions, looking for argument-dependent behaviour, or
* inspects `libsandbox` to see how it encodes filter arguments and whether any internal filter kinds line up with the high codes surfaced here.

Either way, the current experiment’s job is done; its role is to be a fixed backdrop, not an open thread.

---

### On structured agent pairing

This entire result hinged on structured pairing between a web agent and a codex agent. The web agent did not run scripts or see local files; the codex agent did not browse or read the canon directly. Instead, the pattern was:

* the human user seeded the shared context and defined the roles;
* the web agent suggested approaches, constraints, and stopping rules, grounded in public Seatbelt knowledge and general reverse-engineering practice; and
* the codex agent executed those approaches concretely, reported what actually happened on the host, and evolved the local tooling.

That structure mattered because the core conclusion was negative. It is easy to “suspect” that old heuristics won’t work on a modern system; it is much harder to stop trying them unless something, somewhere, turns that suspicion into a documented boundary. The division of labour here made that possible: one side kept the conceptual map and the external literature in view, the other side turned that map into scripts, logs, and commits. When both converged on “the kernel is a VM front-end, not a recoverable Blazakis array,” the project had both a story and a trail of evidence.

For thorny investigations like this—where the risk is not just being wrong, but being seduced by familiar tools—the pairing acts as a control system. It keeps local exploration honest, prevents quiet backsliding into disproven approaches, and leaves behind artifacts that other agents can consume without needing to replay the whole search.
