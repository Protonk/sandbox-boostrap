import Foundation

// MARK: - Concept parsing

func parseClusterTags(from inventoryPath: String) -> [String: [String]] {
    let text = readFile(at: inventoryPath)
    var currentCluster: String?
    var mapping: [String: [String]] = [:]
    for line in text.split(separator: "\n") {
        if line.starts(with: "### ") {
            let title = line.dropFirst(4).trimmingCharacters(in: .whitespaces)
            var slug = slugify(String(title))
            if slug.hasSuffix("-cluster") {
                slug = String(slug.dropLast("-cluster".count))
            }
            currentCluster = slug
            continue
        }
        guard let cluster = currentCluster else { continue }
        if line.trimmingCharacters(in: .whitespaces).hasPrefix("- ") {
            let name = line.replacingOccurrences(of: "- ", with: "")
                .trimmingCharacters(in: .whitespaces)
            var tags = mapping[name] ?? []
            if !tags.contains(cluster) {
                tags.append(cluster)
            }
            mapping[name] = tags
        }
    }
    return mapping
}

func parseConcepts(conceptsPath: String, inventoryPath: String) -> [Concept] {
    let clusterMap = parseClusterTags(from: inventoryPath)
    let text = readFile(at: conceptsPath)
    var concepts: [Concept] = []
    for line in text.split(separator: "\n") where line.starts(with: "## ") {
        let name = line.dropFirst(3).trimmingCharacters(in: .whitespaces)
        let slug = slugify(String(name))
        let clusters = clusterMap[String(name)] ?? []
        concepts.append(
            Concept(
                id: slug,
                name: String(name),
                anchorID: slug,
                clusterTags: clusters,
                notes: nil
            )
        )
    }
    return concepts
}

func parseConceptDetails(mapPath: String, concepts: [Concept]) -> [ConceptDetail] {
    let text = readFile(at: mapPath)
    let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    var details: [ConceptDetail] = []
    var currentName: String?
    var buffer: [String] = []
    func flush() {
        guard let name = currentName else { return }
        let slug = slugify(name)
        let block = buffer
        buffer = []
        currentName = nil

        func extractDefinition(_ lines: [String]) -> String {
            var defLines: [String] = []
            var started = false
            for line in lines {
                if line.trimmingCharacters(in: .whitespaces).isEmpty {
                    if started { break }
                    else { continue }
                }
                if line.hasPrefix("* **Role:**") { break }
                if line.hasPrefix("* **Concrete handles:**") { break }
                if line.hasPrefix("* **Validation pattern:**") { break }
                defLines.append(line.trimmingCharacters(in: .whitespaces))
                started = true
            }
            return defLines.joined(separator: " ").trimmingCharacters(in: .whitespaces)
        }

        func extractRole(_ lines: [String]) -> String? {
            for line in lines where line.contains("**Role:**") {
                if let range = line.range(of: "**Role:**") {
                    let tail = line[range.upperBound...].trimmingCharacters(in: .whitespaces)
                    return tail.trimmingCharacters(in: CharacterSet(charactersIn: "* ").union(.whitespaces))
                }
            }
            return nil
        }

        func extractList(after marker: String, from lines: [String]) -> [String] {
            var capture = false
            var items: [String] = []
            for line in lines {
                if line.contains(marker) {
                    capture = true
                    continue
                }
                if capture {
                    if line.trimmingCharacters(in: .whitespaces).hasPrefix("*") == false && line.hasPrefix("  *") == false {
                        if line.trimmingCharacters(in: .whitespaces).isEmpty { break }
                    }
                    if line.trimmingCharacters(in: .whitespaces).hasPrefix("*") || line.trimmingCharacters(in: .whitespaces).hasPrefix("-") {
                        let trimmed = line.replacingOccurrences(of: "*", with: "")
                            .replacingOccurrences(of: "-", with: "")
                            .trimmingCharacters(in: .whitespaces)
                        if trimmed.contains("Validation pattern:") { continue }
                        if !trimmed.isEmpty {
                            items.append(trimmed)
                        }
                    } else if line.hasPrefix("  *") {
                        let trimmed = line.replacingOccurrences(of: "  *", with: "").trimmingCharacters(in: .whitespaces)
                        if !trimmed.isEmpty {
                            items.append(trimmed)
                        }
                    } else {
                        break
                    }
                }
            }
            return items
        }

        func extractLineValue(prefix: String, from lines: [String]) -> String? {
            for line in lines where line.contains(prefix) {
                if let range = line.range(of: prefix) {
                    let tail = line[range.upperBound...].trimmingCharacters(in: .whitespaces)
                    return tail
                }
            }
            return nil
        }

        let definition = extractDefinition(block)
        let role = extractRole(block)
        let handles = extractList(after: "**Concrete handles:**", from: block)
        let validation = extractList(after: "**Validation pattern:**", from: block)
        let relatedRaw = extractLineValue(prefix: "Related concepts:", from: block) ?? extractLineValue(prefix: "**Related concepts:**", from: block) ?? ""
        let related = relatedRaw
            .split(whereSeparator: { [",", ";"].contains(String($0)) })
            .map { slugify($0.trimmingCharacters(in: .whitespaces)) }
            .filter { !$0.isEmpty }
        let clustersRaw = extractLineValue(prefix: "Clusters:", from: block) ?? ""
        let clusters = clustersRaw
            .split(whereSeparator: { [",", ";"].contains(String($0)) })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        details.append(
            ConceptDetail(
                id: slug,
                definition: definition,
                role: role,
                concreteHandles: handles,
                validationPatterns: validation,
                relatedConcepts: related,
                clusters: clusters
            )
        )
    }

    for line in lines {
        if line.hasPrefix("## ") {
            flush()
            currentName = line.dropFirst(3).trimmingCharacters(in: .whitespaces)
            continue
        }
        if currentName != nil {
            buffer.append(line)
        }
    }
    flush()
    return details
}
