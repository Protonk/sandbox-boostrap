# Symbol Search – Research Report (BootKernelExtensions.kc, 14.4.1 / 23E224)

## Purpose

Recover the sandbox PolicyGraph dispatcher and adjacent helpers by leveraging symbol/string pivots (AppleMatch imports, sandbox strings, MACF hook tables) and structural signatures, rather than relying on computed-jump density.

## Baseline and scope

- Host target: macOS 14.4.1 (23E224), Apple Silicon, SIP enabled (same baseline as other Ghidra experiments).
- Artifacts: `dumps/Sandbox-private/14.4.1-23E224/kernel/BootKernelExtensions.kc`, Ghidra project `dumps/ghidra/projects/sandbox_14.4.1-23E224`.
- Tooling: headless Ghidra scripts in `dumps/ghidra/scripts/` (string refs, tag switch, op-table), `scaffold.py` with `--process-existing` to reuse the analyzed project.
- Concept anchors: dispatcher should walk compiled PolicyGraph nodes (two successors, action terminals), consult operation→entry tables, call AppleMatch for regex filters, and sit downstream of MACF hook glue.

## Planned pivots

- String/import searches for AppleMatch helpers and sandbox identifiers, with caller enumeration.
- MACF `mac_policy_conf` / `mac_policy_ops` traversal to find the shared sandbox check helper invoked by `mpo_*` hooks.
- Header/section signature scans using `.sb.bin` fixtures to find embedded profile structures in KC.
- Cross-correlation of the above to nominate dispatcher/action-handling functions for deeper analysis.

## Reporting

- `Notes.md`: running log of commands, addresses, and shortlists.
- `Plan.md`: staged steps and stop conditions.
- This report: rationale, baseline, and how each pivot ties back to the Seatbelt concepts (PolicyGraph evaluation, operation vocabulary, sandbox label plumbing).
