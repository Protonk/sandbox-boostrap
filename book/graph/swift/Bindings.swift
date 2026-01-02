import Foundation

// MARK: - Concept/text bindings and runtime expectations

func conceptTextBindings() -> [ConceptTextBinding] {
    let path = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        .appendingPathComponent("book/evidence/graph/concepts/concept_text_map.json")
    if let data = try? Data(contentsOf: path),
       let existing = try? JSONDecoder().decode([ConceptTextBinding].self, from: data) {
        return existing
    }
    return []
}

func loadRuntimeExpectations(at path: String) -> RuntimeExpectations? {
    let url = URL(fileURLWithPath: path)
    guard let data = try? Data(contentsOf: url) else { return nil }
    return try? JSONDecoder().decode(RuntimeExpectations.self, from: data)
}

func writeValidationReport(_ report: ValidationReport, to path: String) {
    writeJSON(report, to: path)
}
