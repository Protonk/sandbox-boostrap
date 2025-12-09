import Foundation

// MARK: - Validation strategies

func strategies(concepts: [Concept]) -> [ValidationStrategy] {
    func id(_ name: String) -> String { slugify(name) }
    return [
        ValidationStrategy(
            id: "static-profile-parse",
            kind: .staticFormat,
            description: "Parse compiled sandbox profiles into header/op-table/node/literal structures and assert basic invariants.",
            inputKinds: [.profileBlob],
            outputKinds: [.jsonEvidence],
            primaryConcepts: [
                id("Binary Profile Header"),
                id("Operation Pointer Table"),
                id("PolicyGraph"),
                id("Policy Node"),
                id("Profile Format Variant"),
                id("Regex / Literal Table")
            ],
            secondaryConcepts: [
                id("Compiled Profile Source"),
                id("SBPL Profile")
            ]
        ),
        ValidationStrategy(
            id: "semantic-microprofiles",
            kind: .semanticBehavior,
            description: "Run tiny SBPL profiles and probes to observe operations, filters, metafilters, and resulting allow/deny decisions.",
            inputKinds: [.sourceCode, .markdownText],
            outputKinds: [.ndjsonLog, .markdownNote],
            primaryConcepts: [
                id("Operation"),
                id("Filter"),
                id("Metafilter"),
                id("Decision"),
                id("Action Modifier"),
                id("Policy Node"),
                id("PolicyGraph")
            ],
            secondaryConcepts: [
                id("SBPL Profile"),
                id("SBPL Parameterization")
            ]
        ),
        ValidationStrategy(
            id: "vocab-mapping",
            kind: .vocabularyMapping,
            description: "Extract operation/filter vocabulary tables from compiled blobs and align them with runtime usage.",
            inputKinds: [.profileBlob, .processTrace],
            outputKinds: [.jsonEvidence],
            primaryConcepts: [
                id("Operation Vocabulary Map"),
                id("Filter Vocabulary Map"),
                id("Operation Pointer Table")
            ],
            secondaryConcepts: [
                id("Profile Format Variant"),
                id("PolicyGraph")
            ]
        ),
        ValidationStrategy(
            id: "lifecycle-extensions",
            kind: .lifecycleExtension,
            description: "Probe extension issuance, policy stack composition, and lifecycle behaviors including apply attempts and platform policy checks.",
            inputKinds: [.sourceCode, .processTrace],
            outputKinds: [.ndjsonLog, .markdownNote],
            primaryConcepts: [
                id("Sandbox Extension"),
                id("Policy Lifecycle Stage"),
                id("Profile Layer"),
                id("Policy Stack Evaluation Order"),
                id("Compiled Profile Source")
            ],
            secondaryConcepts: [
                id("SBPL Parameterization"),
                id("SBPL Profile")
            ]
        )
    ]
}
