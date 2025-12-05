# Design: CARTON as Glue for Agentic Building

## Overview

CARTON becomes interesting when it stops being “JSON-with-guardrails” and starts being the place where agents go to answer planning questions about the system.

This design treats CARTON as:

1. A **semantic hub** where names and IDs line up.
2. An **exploration surface** that’s more attractive than `jq` for planning work.
3. A **construction scaffold** that experiments and docs attach to.

Metaphorically: CARTON is the cardboard frame the termites (agents) agree on. They can chew, tunnel, and build, but everyone agrees which beams are load-bearing and where new tunnels attach.

---

## 1. CARTON as Semantic Hub

Today, CARTON mostly says “these JSONs exist, and they’re checked.” To become glue, it needs to be the canonical place where Sonoma Seatbelt identities are reconciled.

Target properties:

* **Single source of naming truth**

  * Every operation/filter ID, every system profile identity, every runtime signature ID is canonicalized in CARTON.
  * Other layers (SBPL snippets, experiment outputs, notes, docs) point *into* CARTON IDs, not directly into ad-hoc paths or names.

* **Crosswalk between worlds**

  * SBPL profile → CARTON system profile ID → operations/filters → runtime signatures → experiments.
  * Runtime trace or experiment output → CARTON signature/profile IDs → back to SBPL and conceptual docs.

* **Fact anchor for the textbook**

  * When a doc states, “On this host, `mach-lookup` appears in X profiles and Y runtime signatures,” those counts and identities are derived from CARTON, not recomputed ad-hoc.

This is what makes the cardboard load-bearing: different agents can build and revise around CARTON, but they share the same structural reference frame.

---

## 2. CARTON as Exploration Surface

The hardened API (`profiles_and_signatures_for_operation`) is a good start but still nearly equivalent to “a couple of jq filters.” To be genuinely useful, CARTON must support the questions agents actually ask when they’re planning work, not just checking a single fact.

Examples of questions that should be answered by one-line CARTON queries:

* **Coverage-oriented questions**

  * “Which ops have zero runtime coverage?”
  * “Which ops appear only in `sys:bsd`?”
  * “Which ops appear in runtime but in no frozen system profile?”

* **Profile-centric questions**

  * “Given this system profile, what operations/filters does it exercise?”
  * “Which runtime signatures touched those operations?”

* **Diff/contrast questions**

  * “What operations distinguish profile A from profile B?”
  * “Which ops are unique to sandbox X vs a baseline?”

* **Experiment planning questions**

  * “Show me ops with low coverage and high conceptual importance.”
  * “For each such op, suggest a profile+signature pair to start from.”

The API becomes more attractive than `jq` when:

* There is a **small vocabulary of high-level queries** (op-centric, profile-centric, coverage, diff) that directly match these questions.
* Returns are **structured for chaining** (IDs and names ready to feed into other queries, results sorted by “interestingness” where appropriate).
* Failure modes are **safe and predictable** (which the current error contracts already support), so agents can explore without fear of opaque breakage.

In termite terms: the tunnels are already half-dug. Agents can explore coverage, profiles, and diffs declaratively instead of hand-parsing mappings.

---

## 3. CARTON as Construction Scaffold

Glue is about connecting things that wouldn’t otherwise stick together. For CARTON, that means being the structural frame that experiments and documentation attach to.

Key aspects:

* **Experiments keyed by CARTON IDs**

  * Every experiment output that mentions an operation/profile/signature does so via CARTON IDs.
  * A query layer can then answer:

    * “Show me all experiments that exercised this op/profile.”
    * “List runtime signatures that have a confirmed golden experiment behind them.”

* **Documentation keyed by CARTON IDs**

  * API docs, SBPL exemplars, “golden stories,” and notebook writeups hang off the same IDs:

    * “Explain `mach-lookup`” → resolve via CARTON → follow links to SBPL examples, experiments, and narrative docs anchored on that ID.

* **Attachment points for new agents**

  * When a new agent proposes a probe, it selects operations and profiles from CARTON; output is keyed by those IDs.
  * New work becomes immediately composable with the existing stock because everyone is speaking in the same ID space.

Here, CARTON is not “the whole nest”; it’s the rigid frame. Tunnels, chambers, and new additions must attach to it. That frame is what keeps the structure coherent and what lets later agents understand and extend earlier work.

---

## Near-Term Moves to Push CARTON Toward Glue

Without expanding scope too far, the next steps that move CARTON from “hardened JSON wrapper” toward “agent glue” are:

1. **Introduce a small “coverage + profile” query set**

   Building on the existing single-op query, add:

   * `ops_with_coverage(profile=None, runtime=None, zero_only=False)`

     * Answers: “which ops have zero runtime coverage,” “which ops are present in `sys:bsd`,” “which ops appear only in runtime,” etc.

   * `operations_for_profile(profile_id)`

     * Returns ops (names + IDs) exercised by a given system profile and the runtime signatures that touched them.

   * Optionally, a simple diff: `diff_profiles(a, b)`

     * Returns ops/filters unique to each profile and those shared.

   These directly support common exploratory and planning questions and are meaningfully more convenient than `jq`.

2. **Adopt an “attachment” convention for experiments and docs**

   * Standardize that experiments and narrative docs reference CARTON identities explicitly (operation IDs, profile IDs, signature IDs).
   * Even a small mapping (e.g., “op_id → [doc paths, experiment IDs]”) that CARTON can surface is enough to start linking.

Once these exist:

* Serious outputs (experiments, docs) point into CARTON.
* Serious planning queries go through CARTON.
* Agents start from CARTON when asking, “What should I poke next?”

At that point, CARTON is no longer just validated JSON; it is the cardboard scaffold the termites build on and around—a genuine piece of glue in the system.
