# Examples and Concept Clusters

This file maps each `book/examples/` directory to the concept-validation clusters from `CONCEPT_INVENTORY.md`:

- **Static-Format** – compiled profile structure, headers, operation tables, regex/literal tables, format variants.
- **Semantic Graph and Evaluation** – operations, filters, metafilters, decisions, policy graph behavior.
- **Vocabulary and Mapping** – operation/filter vocab maps and name↔ID alignment.
- **Runtime Lifecycle and Extension** – profile layers, stack evaluation order, compiled profile source, containers, entitlements, extensions, adjacent controls.

For each example, clusters are listed as **Primary** (P) and **Secondary** (S).

---

- `entitlements-evolution/` – Prints signing identifier and entitlements for the running binary; meant to compare differently signed builds to see how entitlement-backed filters drive policy differences.  
  Clusters: **P:** Runtime Lifecycle and Extension (entitlements as lifecycle inputs); **S:** Semantic Graph and Evaluation (entitlement-backed filters), Vocabulary and Mapping (entitlement keys and filter names).

- `platform-policy-checks/` – Probe sysctl, SIP-protected paths, and Mach services to surface platform/SIP denies that precede or override per-process SBPL.  
  Clusters: **P:** Runtime Lifecycle and Extension (Profile Layer, Policy Stack Evaluation Order, adjacent controls); **S:** Semantic Graph and Evaluation (operations and filters hit by the probes).

- `extensions-dynamic/` – Calls `sandbox_extension_issue/consume/release`; expects issuance to fail without entitlements but illustrates the token workflow that feeds `(extension ...)` filters.  
  Clusters: **P:** Runtime Lifecycle and Extension (Sandbox Extension, label state); **S:** Semantic Graph and Evaluation (extension filters and resulting decisions).

- `containers-and-redirects/` – Walks `~/Library/Containers` and group containers, resolves symlinks, and shows the canonical paths the sandbox evaluates.  
  Clusters: **P:** Runtime Lifecycle and Extension (Container, filesystem view); **S:** Semantic Graph and Evaluation (path and vnode filters).

- `mach-services/` – Registers a bootstrap service and looks it up alongside selected system services to show how `mach-lookup` and `(global-name ...)` filters behave.  
  Clusters: **P:** Semantic Graph and Evaluation (mach-lookup operation, global-name filters); **S:** Vocabulary and Mapping (service-name/global-name vocab entries).

- `network-filters/` – Exercises TCP/UDP/UNIX sockets to map syscall patterns to `network-*` operations and filters (domain, type, remote/local addresses).  
  Clusters: **P:** Semantic Graph and Evaluation (network operations and filters); **S:** Vocabulary and Mapping (socket-domain/type and network filter vocab).

- `metafilter-tests/` – Runs tiny SBPL profiles under `sandbox-exec` to demonstrate `require-any`, `require-all`, and `require-not` behavior on `file-read*`.  
  Clusters: **P:** Semantic Graph and Evaluation (Metafilter, PolicyGraph shape); **S:** Static-Format (compiled graphs corresponding to SBPL metafilters).

- `sbpl-params/` – Demonstrates `(param "...")` SBPL templating and how passing parameter dictionaries changes allowed paths under `sandbox-exec`.  
  Clusters: **P:** Semantic Graph and Evaluation (SBPL Parameterization as part of semantic profile); **S:** Runtime Lifecycle and Extension (parameters supplied at compile/launch time).

- `apple-scheme/` – C shim that calls `sandbox_compile_file` on `profiles/demo.sb` and writes `build/demo.sb.bin` (modern graph format).  
  Clusters: **P:** Static-Format (Binary Profile Header, Profile Format Variant); **S:** Runtime Lifecycle and Extension (Policy Lifecycle Stage: SBPL compilation).

- `extract_sbs/` – Compiles system profiles (default `airlock.sb`, `bsd.sb`) with `libsandbox` and saves `.sb.bin` blobs.  
  Clusters: **P:** Static-Format (captured compiled profiles, format variants); **S:** Runtime Lifecycle and Extension (Compiled Profile Source: system templates).

- `libsandcall/` – Compiles inline SBPL, prints bytecode metadata, and attempts `sandbox_apply` (expected to EPERM without special entitlements).  
  Clusters: **P:** Runtime Lifecycle and Extension (Policy Lifecycle Stage, applying profiles to labels); **S:** Static-Format (compiled blob structure), Semantic Graph and Evaluation (effects of applied profiles when they succeed).

- `re2dot/` – Converts AppleMatch regex blobs (`.re`) from compiled profiles into Graphviz `.dot` graphs.  
  Clusters: **P:** Static-Format (Regex/Literal Table, AppleMatch NFA representation); **S:** Vocabulary and Mapping (which filters/operations reference given regexes).

- `resnarf/` – Extracts AppleMatch regex blobs from early decision-tree profiles using header `re_table_offset/count` fields.  
  Clusters: **P:** Static-Format (legacy regex tables and profile formats); **S:** Vocabulary and Mapping (linking extracted regexes back to filters/operations via IDs).

- `sb/` – Compiles `sample.sb`, then parses the resulting modern graph-based blob via the shared ingestion layer.  
  Clusters: **P:** Static-Format (header, operation pointer table, node graph, literal/regex tables); **S:** Semantic Graph and Evaluation (PolicyGraph reconstruction), Vocabulary and Mapping (operation/filter IDs for the sample).

- `sbdis/` – Disassembles legacy decision-tree profiles into per-operation filter trees and decoded regexes (uses shared ingestion for slicing).  
  Clusters: **P:** Static-Format (legacy node/regex layout, format variants); **S:** Semantic Graph and Evaluation (operation/filter semantics in early formats), Vocabulary and Mapping (name↔ID reconstruction).

- `sbsnarf/` – Compiles arbitrary SBPL files to `.sb.bin` via `sandbox_compile_file` (no apply).  
  Clusters: **P:** Static-Format (compiled blob production across formats); **S:** Runtime Lifecycle and Extension (Compiled Profile Source for test/harness profiles).
