>SUBSTRATE_2025-frozen
## 1. SANDBLASTER2016

SandBlaster is a 2016 reverse-engineering paper that introduces a toolchain for decompiling Apple’s binary sandbox profiles back into human-readable SBPL, focusing on iOS 7–9 but explicitly built on the sandbox implementation in the shared XNU kernel used by both iOS and Mac OS X (platform-unspecified, but naming both OSes). iOS-only: The concrete targets are built-in iOS sandbox profiles (notably including the default “container” profile for third-party apps) stored as binary serialized graphs in iOS firmware images. macOS-specific: The authors compile their reversed SBPL profiles on Mac OS X to validate syntactic correctness, revealing that some SBPL tokens differ between iOS and Mac OS X but that the overall language and profile structure are compatible. Inference: likely shared mechanism for macOS Seatbelt—because the sandbox resides in XNU and profiles are written in SBPL on both platforms, SandBlaster’s findings on profile structure, binary representation, default decisions, metafilters, and implicit rules are highly likely to describe macOS sandbox behaviour as well, even though the paper does not study macOS policies directly.

---

## 2. Architecture pipeline (as seen through this paper)

### 2.1 High-level sandbox placement in the OS

* Platform-unspecified (iOS and Mac OS X, both named): The paper describes the “Apple sandbox” as a kernel-level security layer implemented as part of the XNU kernel, using the TrustedBSD MAC framework, and used “on Mac OS X and iOS” to confine apps or system processes to a subset of actions defined in a sandbox profile. These actions are explicitly said to be system calls and system-call arguments.
* iOS-only: The primary use case studied is iOS, where “every third party application and many system applications” are sandboxed via profiles. macOS-specific use cases are not discussed beyond noting that sandboxing is used there to limit damage from malware or exploited processes. 

Attack model in this architectural sense is generic and platform-unspecified: the sandbox is described as a mitigation to “reduce the damage of malware or an exploited app or system process,” but no concrete attack chains are given for either OS. 

### 2.2 Profile storage and loading (iOS focus)

* iOS-only: SandBlaster reverses where and how iOS stores compiled sandbox profiles:

  * iOS 2–4: profiles stored as separate binary blobs inside the sandbox kernel extension `com.apple.security.sandbox`.
  * iOS 5–8: profiles stored as separate binary blobs inside `/usr/libexec/sandboxd`.
  * iOS 9: all profiles bundled together in a single binary blob inside `com.apple.security.sandbox`.
    In iOS ≤8 each profile has its own blob with a name pointer and a profile‐data pointer/length structure; from iOS 9 onwards, profile metadata and data are bundled into one structure.

* iOS-only: The reversing pipeline is based entirely on iOS firmware files (`.ipsw`) downloaded from Apple, which contain an encrypted root filesystem and encrypted kernel (kernelcache). The authors use published firmware keys plus standard reverse-engineering tools (e.g., `vfdecrypt`, `dmg2img`, and others) to decrypt and unpack the firmware, mount the root filesystem, and extract the iOS `sandboxd` binary, the `com.apple.security.sandbox` kernel extension, and `libsandbox.dylib`. 

* macOS-specific: Mac OS X appears here as the “compilation platform” for validating reversed profiles: the authors compile the SBPL they reconstructed on Mac OS X and note that only minor changes are needed due to differences in tokens between iOS and Mac OS X. 

* Inference: likely shared mechanism on macOS: The fact that the iOS sandbox profiles are stored as binary serialized graphs inside `com.apple.security.sandbox` and that the same kernel extension name is used is strong evidence that macOS also uses binary graph representations of profiles inside its sandbox kernel extension, even though the paper does not state this for macOS explicitly. This inference is about internal representation, not target paths or file layout on disk.

### 2.3 Logical enforcement pipeline (as reflected by the binary format)

Within the paper’s scope, the enforcement pipeline is visible mainly at the “policy graph” level, not at syscall hook sites:

* Platform-unspecified: An Apple sandbox profile is defined as a list of rules, each rule pairing an “operation” (e.g., `file-read*`, `network-outbound`, `signal`, `mach-lookup`) with a decision (`allow` or `deny`) plus zero or more filters. The profile also defines a default decision used for operations not explicitly covered.

* iOS-only: In iOS 9.3.1, the authors report that 103 of 121 built-in profiles use `deny` as the default decision, confirming a default-deny, allow-list style in practice for iOS profiles. 

* Platform-unspecified: Compiled profiles are described as serialized graphs: each “operation node” encodes filters and decisions, connected via edges to “allow”, “deny”, or other non-terminal nodes. There is a dedicated default operation node whose decision is used when no rule matches. The paper’s “reversing operation nodes” section specifies how to interpret match vs. unmatch transitions and how to reconstruct `require-not`, `require-any`, and `require-all` metafilters from the graph.

* Inference: likely similar on macOS: Because the authors successfully compile reversed iOS profiles as SBPL on Mac OS X, and because they state that iOS and Mac OS X sandbox implementations are “similar” due to using the same kernel, it is reasonable to infer that macOS also compiles SBPL into a comparable graph representation with default decisions and metafilter encodings, even though the paper does not show macOS graphs. This inference is about internal representation, not about particular policies.

The paper does not discuss entitlements, XPC services, containers as directory structures, or the exact mapping from app metadata to profiles; it stops at the level of profiles, binary representation, and the SBPL language.

---

## 3. Language and policy model (as seen here)

### 3.1 SBPL and rule structure

* Platform-unspecified: The sandbox policy language is described as a Scheme-like language called SBPL (Sandbox Profile Language). Profiles are initially written in SBPL, then compiled to a binary format consisting of serialized graphs.

* Platform-unspecified: The high-level SBPL structure is: a profile declares a `sandbox_profile`, a default decision, and multiple rules of the form `(operation decision [filters...])`. Operations are atomic “actions” such as file, network, Mach, or signal operations; filters include file-path regular expressions, vnode type filters, and extension filters. Examples in the paper show operations such as `file-read*` with `regex` filters and `vnode-type` filters, and rules that operate on device nodes or launchd sockets.

* iOS-only: The authors emphasize that built-in iOS profiles for iOS 7–9, particularly the default “container” profile for third-party apps, follow this model and can be reversed fully to SBPL. However, the contents of the container profile are not enumerated; the paper just states that having the profile in SBPL “allows critical analysis” of security and privacy properties for iOS apps.

* macOS-specific: The reversed profiles are compiled on Mac OS X to validate syntactic correctness. The authors note that “minor modifications” are necessary because some tokens differ between iOS and Mac OS X (e.g., platform-specific identifiers), but they do not list the differences. 

### 3.2 Metafilters and complex conditions

* Platform-unspecified: The policy model includes three SBPL “metafilters” that operate on filters and entire rule fragments:

  * `require-any`: logical OR across a list of filters or subconditions.
  * `require-all`: logical AND across a list of filters or subconditions.
  * `require-not`: logical negation of a filter or subcondition.
    Examples show, for instance, `file-read*` being allowed if either a `regex` or a `vnode-type` filter matches (`require-any`), or only if both a `regex` and an `extension` filter match (`require-all`). `require-not` is used to allow operations only when a given filter does not match.

* Platform-unspecified: The paper explains in detail how these metafilters are encoded as graph structures and how SandBlaster reconstructs them: `require-not` is implemented by “negating” nodes (swapping match/unmatch actions), and nested combinations of `require-any` and `require-all` are recovered by aggregating sibling nodes (for OR) and parent/child relationships (for AND). 

* iOS-only: The authors note that prior tools they build upon (Esser’s) do not handle metafilters properly, whereas SandBlaster does, making its output closer to the original SBPL for iOS profiles.

* Inference: likely shared mechanism on macOS: Because SBPL is presented as the common profile language for the “Apple sandbox” and because Mac OS X successfully compiles SBPL with the same metafilter syntax, it is reasonable to infer that macOS profiles also make use of `require-any`, `require-all`, and `require-not` in the same way. The paper does not demonstrate any specific macOS profile that uses them.

### 3.3 Implicit SBPL rules

* Platform-unspecified: By examining `libsandbox.dylib` and experimenting with custom profiles, the authors find that the sandbox compiler injects implicit SBPL rules into profiles. A listing in the paper shows SBPL-like code defining helper predicates `allowed?` and `denied?` and then:

  * Allowing `mach-bootstrap` if `mach-lookup` is ever allowed.
  * Allowing `network-outbound` to a WebDAV agent socket if `file-read*` is not denied (with a comment referencing a specific bug workaround).
  * Denying `network-outbound` to launchd sockets (both a literal path and a regex for launchd socket paths).
  * Always allowing `signal` when the target is `self`.
    These are characterized as “implicit SBPL rules for sandbox profiles” that SandBlaster removes when cleaning up reversed profiles, so that human readers are not confused by compiler-injected boilerplate. 

* Platform-unspecified: The authors use these implicit rules to guide a “cleanup” phase in which they remove explicit operation rules whose decision matches the default decision, and remove implicit regex patterns that are known to be compiled into the binary regardless of the profile’s SBPL.

* macOS-specific: The authors state that when they compile reversed profiles on Mac OS X, they must account for tokens that differ between iOS and Mac OS X, implying that the implicit rules discovered from `libsandbox.dylib` are also relevant to Mac OS X’s SBPL compilation semantics, though they do not show Mac-specific code snippets. 

* Inference: likely shared mechanism on macOS: Because these implicit rules are derived from `libsandbox.dylib` (which exists on both platforms) and are not tied to iOS-specific paths alone (e.g., launchd sockets, signals, Mach bootstrap/lookup are generic), it is reasonable to infer that analogous implicit SBPL rules are present for macOS sandbox profiles, affecting how capabilities are actually enforced versus what is visible in the explicit SBPL. The paper does not explicitly confirm this for macOS.

### 3.4 What the paper does not cover

* iOS-only: The “container” profile for third-party apps is singled out as particularly important, but the paper does not list its rules or discuss containers as filesystem directories.
* Not in this paper: There is no discussion of entitlements, XPC services, App Sandbox UI configuration, or how profiles are selected based on app metadata on either iOS or macOS.
* Not in this paper: No explicit comparison between specific iOS and macOS profiles, and no examples of macOS-only profiles.

---

## 4. Enforcement mechanics and bypass chains

### 4.1 Enforcement mechanics at the profile-graph level

* Platform-unspecified: The binary format for a sandbox profile is described as a directed acyclic graph with operation nodes and terminal decision nodes (`allow`, `deny`). Each operation node contains filters and references to other nodes; evaluation of an action corresponds to walking this graph based on whether filters match or not. A default operation (with a default decision) is used when no rule matches.

* Platform-unspecified: The paper gives a truth-table-style description for how “negate” (used to implement `require-not`) interacts with match/unmatch outcomes and terminal vs. non-terminal nodes, guiding how to reconstruct `require-not` from the graph. For example, when a node that would normally match and go to `deny` is negated, the negated version matches and goes to `allow`. The authors then show how to use node aggregation to build nested `require-any` and `require-all` structures from graph topology. 

* Platform-unspecified: Regular expressions in filters are serialized within the binary format; SandBlaster includes logic to deserialize these regexes so the reversed SBPL uses readable regex syntax again.

* Platform-unspecified: The implicit SBPL rules derived from `libsandbox.dylib` (Section 3.3) describe enforcement semantics that are not evident from explicit SBPL, such as always allowing signaling self and always denying outbound network access to launchd sockets. These effectively add hidden allow/deny rules that apply across profiles. 

* iOS-only: The statistics about default decisions (e.g., majority default-deny profiles in iOS 9.3.1) and the enumeration of built-in profiles are based solely on iOS firmware and profiles; the paper does not provide analogous macOS statistics. 

* macOS-specific: When reversed iOS profiles are compiled on Mac OS X, minor syntactic edits are needed due to token differences, but the overall graph-to-SBPL mapping does not change; this suggests that enforcement logic at the graph level is compatible between platforms. 

### 4.2 Attack models and chains

* Platform-unspecified attack model (very high level): The introduction frames the sandbox as a mechanism “to limit the damage of malware on Mac OS X and iOS,” protecting against exploited apps or system processes. This implies the starting point is arbitrary code execution inside a sandboxed process, and the goal is to constrain further damage to the system. However, the paper does not formalize a threat model beyond this brief description. 

* iOS-only attack context: The emphasis on the iOS container profile and built-in profiles is motivated by wanting to understand how iOS constrains third-party apps and system apps, but no exploitation case studies are provided. The authors state that reversed profiles “allow critical analysis” of security and privacy features for iOS apps, and that future work would include mapping running apps to reversed profiles on a jailbroken device to validate semantic correctness.

* macOS-specific attack model: The only macOS-specific angle is that the same sandbox mechanism is claimed to mitigate malware on Mac OS X, and that Mac OS X is used as a compilation platform. No macOS-specific attack chains are described, and no macOS-specific weaknesses are demonstrated.

* Not in this paper: There are no concrete sandbox bypass or escape techniques described for either iOS or macOS. The paper does not show how an attacker could use profile weaknesses to read/write outside expected scope, pivot to unsandboxed components, or gain additional privileges. All exploitation-oriented reasoning must be supplied by the reader based on the reversed profiles; SandBlaster itself is a tooling contribution, not an exploitation paper.

Given this, there are no “attack chains” to enumerate with starting conditions and end capabilities; the only step-by-step narratives in the paper describe the reversing algorithms and firmware-extraction process, not adversarial sandbox escapes.

---

## 5. Patterns, idioms, and macOS-relevant implications for a capability catalog

### 5.1 Recurring patterns and idioms

* iOS-only patterns (concrete data):

  * Extensive use of default-deny: most iOS 9.3.1 built-in profiles (103/121) use `deny` as the default decision; the rest are not detailed. 
  * Many profiles (including the container profile) rely heavily on SBPL operations like `file-read*`, `file-write*`, `network-outbound`, `signal`, and Mach-related operations, combined with regex path filters and vnode-type filters.
  * Profiles are compiled into binary graphs embedded in `com.apple.security.sandbox` or `/usr/libexec/sandboxd`, depending on iOS version.

* Platform-unspecified idioms:

  * Use of metafilters (`require-any`, `require-all`, `require-not`) to build complex context conditions, sometimes nested, with semantics implemented via graph transformations.
  * Compiler-injected implicit rules that apply across profiles, such as:

    * Always allowing `signal` to self.
    * Conditional allowances for `mach-bootstrap` and WebDAV-related network-outbound.
    * Hardcoded denies for outbound connections to launchd sockets. 

* macOS-specific glimpses:

  * Reversed iOS SBPL compiles on Mac OS X with only minor token edits, demonstrating that Mac OS X shares the same SBPL semantics and that its sandbox compiler behaves similarly at a structural level. 

### 5.2 What SandBlaster gives an expert macOS capability catalog

Direct macOS-specific contributions (explicit in the paper):

* macOS-specific: The paper confirms that the same sandbox system (within XNU, using TrustedBSD MAC and SBPL) is used on Mac OS X and iOS, and that Mac OS X can compile iOS-style SBPL profiles with minimal adjustments. This is a direct statement that macOS Seatbelt shares core mechanisms with the iOS sandbox.
* macOS-specific: It shows that Mac OS X’s `libsandbox` recognizes essentially the same SBPL constructs as the iOS compiler, only differing in some platform-specific tokens.

These are useful for a capability catalog because they justify reusing an operation-centric SBPL model for macOS, and they support the assumption that macOS profiles are compiled into binary graphs with similar structure.

iOS-only but structurally informative content:

* iOS-only: Profile inventory (number of built-in profiles, container profile emphasis, storage locations) and the default-deny statistics are specific to iOS versions 7–9. These cannot be transferred directly to macOS but suggest what a comparable macOS inventory might look like.
* iOS-only: The firmware-extraction methodology is entirely iOS-centric.

Inference: likely macOS-relevant mechanisms and catalog annotations

Given the explicit shared-kernel statement and Mac OS X compilation tests, it is reasonable (but still an inference) to adapt several findings to macOS Seatbelt for catalog purposes:

* Inference: core capability dimensions for macOS: The operations illustrated in SBPL examples (e.g., `file-read*`, `file-write*`, `network-outbound`, `signal`, Mach operations) look like a natural basis for operation-level capability entries in a macOS catalog, because they are presented as generic “Apple sandbox” operations, not iOS-specific features. The paper, however, does not enumerate the full operation set.

* Inference: default-deny semantics: The iOS data (majority default-deny) support annotating macOS capabilities with the expectation that system and app sandboxes are designed as default-deny, allow-list policies. This should be marked as inferred, because the paper does not measure macOS profiles.

* Inference: implicit rules as hidden capability modifiers: The implicit SBPL rules discovered in `libsandbox.dylib` show that some capabilities are always present (signal self) and some are always denied (launchd socket connections), independent of explicit SBPL. For a macOS capability catalog, it is sensible to include a separate “implicit rules / compiler boilerplate” layer that captures such always-on or always-off operations, with a note that this is inferred from SandBlaster’s analysis and may apply to macOS as well. 

* Inference: graph-based enforcement and metafilters: Since profiles compile to graphs where metafilters are encoded structurally, a macOS catalog should not treat SBPL rules as isolated lines, but as parts of a graph that may implement complex conditions (e.g., nested AND/OR/NOT over filters). The paper’s reversing algorithms suggest that vulnerabilities might hide in specific combinations of filters and default decisions, rather than in any single allow rule, even though SandBlaster itself does not examine vulnerabilities. 

### 5.3 What the paper does not provide for macOS

* Not in this paper: No macOS-specific profiles, entitlements, containers, XPC services, or helper-based techniques are analysed.
* Not in this paper: No explicit macOS sandbox bypass, no description of how to pivot from a sandboxed macOS app to unsandboxed code, and no examples of reading/writing outside macOS containers.
* Not in this paper: No discussion of macOS version evolution (e.g., 10.x releases), App Sandbox configuration, or adoption.

In summary, SandBlaster’s value for a macOS capability catalog is structural rather than exploit-specific: it confirms the SBPL/graph model, reveals the existence of compiler-injected implicit rules, and provides concrete examples of operations and metafilters. An expert using this paper would mine it for the language and representation details and then pair those with separate macOS-focused work (not present here) to identify actual weak capabilities and bypass techniques.
