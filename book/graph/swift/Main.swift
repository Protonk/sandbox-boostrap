import Foundation

// MARK: - Entry point

@main
struct GraphChecks {
    static func main() {
        let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)

        // Parse concept sources from book/substrate + inventory markdown
        let concepts = parseConcepts(
            conceptsPath: root.appendingPathComponent("book/substrate/Concepts.md").path,
            inventoryPath: root.appendingPathComponent("book/evidence/graph/concepts/CONCEPT_INVENTORY.md").path
        )
        // Enrich with validation-friendly detail blocks
        let conceptDetails = parseConceptDetails(
            mapPath: root.appendingPathComponent("book/graph/concepts/validation/Concept_map.md").path,
            concepts: concepts
        )
        let strategyList = strategies(concepts: concepts)
        let bindings = conceptTextBindings()

        // Emit core JSON artifacts
        writeJSON(concepts, to: root.appendingPathComponent("book/evidence/graph/concepts/concepts.json").path)
        writeJSON(conceptDetails, to: root.appendingPathComponent("book/evidence/graph/concepts/concept_map.json").path)
        writeJSON(strategyList, to: root.appendingPathComponent("book/evidence/graph/concepts/validation/strategies.json").path)
        writeJSON(bindings, to: root.appendingPathComponent("book/evidence/graph/concepts/concept_text_map.json").path)

        // Lightweight validation report (non-fatal)
        var errors: [String] = []
        var warnings: [String] = []
        let conceptIDs = Set(concepts.map { $0.id })
        for strat in strategyList {
            for cid in strat.primaryConcepts + strat.secondaryConcepts {
                if conceptIDs.contains(cid) == false {
                    errors.append("strategy \(strat.id) references missing concept \(cid)")
                }
            }
        }
        if let runtimeExp = loadRuntimeExpectations(at: root.appendingPathComponent("book/evidence/graph/mappings/runtime/expectations.json").path) {
            for prof in runtimeExp.profiles {
                if prof.status.isEmpty {
                    warnings.append("runtime profile \(prof.profile_id) has empty status")
                }
            }
        } else {
            warnings.append("runtime expectations not found or unreadable")
        }
        let report = ValidationReport(
            errors: errors,
            warnings: warnings,
            checked: ["concepts", "strategies", "runtime_expectations"]
        )
        let reportPath = root.appendingPathComponent("book/evidence/graph/concepts/validation/validation_report.json").path
        writeValidationReport(report, to: reportPath)
    }
}
