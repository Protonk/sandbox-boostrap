import Foundation

// MARK: - Entry point

@main
struct GraphChecks {
    static func main() {
        let root = repoRootURL()

        let parsed = parseConceptMap(
            mapPath: root.appendingPathComponent("book/integration/carton/Concept_map.md").path
        )

        let conceptDetails = parsed.map { $0.detail }
        let concepts = parsed.map { parsedConcept in
            Concept(
                id: parsedConcept.detail.id,
                name: parsedConcept.name,
                anchorID: parsedConcept.detail.id,
                clusterTags: parsedConcept.detail.clusters.map { slugify($0) },
                notes: nil
            )
        }

        let base = root.appendingPathComponent("book/evidence/syncretic/concepts")
        writeJSON(concepts, to: base.appendingPathComponent("concepts.json").path)
        writeJSON(conceptDetails, to: base.appendingPathComponent("concept_map.json").path)
    }
}
