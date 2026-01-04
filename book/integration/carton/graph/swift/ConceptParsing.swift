import Foundation

// MARK: - Concept parsing

struct ParsedConcept {
    let name: String
    let detail: ConceptDetail
}

private enum Section {
    case definition
    case concrete
    case validation
}

private func splitListValues(_ raw: String) -> [String] {
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed
        .split(whereSeparator: { $0 == ";" || $0 == "," })
        .map { $0.trimmingCharacters(in: CharacterSet(charactersIn: " .")) }
        .filter { !$0.isEmpty }
}

private func parseBulletItem(_ line: String) -> String? {
    let trimmed = line.trimmingCharacters(in: .whitespaces)
    if trimmed.hasPrefix("* ") || trimmed.hasPrefix("- ") {
        let item = trimmed.dropFirst(2).trimmingCharacters(in: .whitespaces)
        return item.isEmpty ? nil : String(item)
    }
    return nil
}

private func extractInlineValue(from line: String, label: String) -> String? {
    guard let range = line.range(of: label) else { return nil }
    let tail = line[range.upperBound...]
    return tail.trimmingCharacters(in: CharacterSet(charactersIn: "* ").union(.whitespaces))
}

private func parseConceptBlock(name: String, lines: [String]) -> ParsedConcept {
    let slug = slugify(name)
    var definitionLines: [String] = []
    var role: String?
    var concreteHandles: [String] = []
    var validationPatterns: [String] = []
    var relatedConcepts: [String] = []
    var clusters: [String] = []
    var section: Section = .definition

    for line in lines {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty {
            continue
        }

        if let roleValue = extractInlineValue(from: line, label: "Role:") {
            role = roleValue.isEmpty ? nil : roleValue
            continue
        }
        if line.contains("Concrete handles:") {
            section = .concrete
            continue
        }
        if line.contains("Validation pattern:") {
            section = .validation
            continue
        }
        if let relatedValue = extractInlineValue(from: line, label: "Related concepts:") {
            relatedConcepts = splitListValues(relatedValue).map { slugify($0) }
            continue
        }
        if trimmed.hasPrefix("Clusters:") {
            let raw = trimmed.dropFirst("Clusters:".count)
            clusters = splitListValues(String(raw))
            continue
        }

        switch section {
        case .definition:
            definitionLines.append(trimmed)
        case .concrete:
            if let item = parseBulletItem(line) {
                concreteHandles.append(item)
            } else if !concreteHandles.isEmpty {
                concreteHandles[concreteHandles.count - 1] += " " + trimmed
            }
        case .validation:
            if let item = parseBulletItem(line) {
                validationPatterns.append(item)
            } else if !validationPatterns.isEmpty {
                validationPatterns[validationPatterns.count - 1] += " " + trimmed
            }
        }
    }

    let definition = definitionLines.joined(separator: " ").trimmingCharacters(in: .whitespaces)
    return ParsedConcept(
        name: name,
        detail: ConceptDetail(
            id: slug,
            definition: definition,
            role: role,
            concreteHandles: concreteHandles,
            validationPatterns: validationPatterns,
            relatedConcepts: relatedConcepts,
            clusters: clusters
        )
    )
}

func parseConceptMap(mapPath: String) -> [ParsedConcept] {
    let text = readFile(at: mapPath)
    let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    var parsed: [ParsedConcept] = []
    var currentName: String?
    var buffer: [String] = []

    func flush() {
        guard let name = currentName else { return }
        parsed.append(parseConceptBlock(name: name, lines: buffer))
        currentName = nil
        buffer = []
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

    return parsed
}
