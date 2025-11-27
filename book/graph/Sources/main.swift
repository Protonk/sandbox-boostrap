import Foundation

// MARK: - Typealiases

public typealias ConceptID = String
public typealias ValidationID = String
public typealias ExampleID = String
public typealias TextRegionID = String

// MARK: - Enums

public enum ValidationKind: String, Codable {
    case staticFormat
    case semanticBehavior
    case vocabularyMapping
    case lifecycleExtension
    case other
}

public enum InputKind: String, Codable {
    case profileBlob
    case processTrace
    case sourceCode
    case markdownText
    case other
}

public enum OutputKind: String, Codable {
    case jsonEvidence
    case markdownNote
    case ndjsonLog
    case other
}

// MARK: - Nodes

public struct Concept: Codable {
    public let id: ConceptID
    public let name: String
    public let anchorID: String
    public let clusterTags: [String]
    public let notes: String?
}

public struct ValidationStrategy: Codable {
    public let id: ValidationID
    public let kind: ValidationKind
    public let description: String
    public let inputKinds: [InputKind]
    public let outputKinds: [OutputKind]
    public let primaryConcepts: [ConceptID]
    public let secondaryConcepts: [ConceptID]
}

public struct ExampleCode: Codable {
    public let id: ExampleID
    public let paths: [String]
    public let language: String
    public let description: String
    public let chapterBindings: [TextRegionID]
    public let tags: [String]
}

public struct TextRegion: Codable {
    public let id: TextRegionID
    public let chapterNumber: Int
    public let subchapterNumber: Int
    public let title: String
    public let file: String
    public let anchorID: String
}

public struct ConceptTextBinding: Codable {
    public let concept: ConceptID
    public let regions: [TextRegionID]
}

public struct ConceptDetail: Codable {
    public let id: ConceptID
    public let definition: String
    public let role: String?
    public let concreteHandles: [String]
    public let validationPatterns: [String]
    public let relatedConcepts: [ConceptID]
    public let clusters: [String]
}

// MARK: - Helpers

func slugify(_ raw: String) -> String {
    let lower = raw.lowercased()
    let filtered = lower.compactMap { ch -> String? in
        if ch.isLetter || ch.isNumber {
            return String(ch)
        }
        if ch == " " || ch == "-" {
            return " "
        }
        return nil
    }.joined()
    let parts = filtered.split(whereSeparator: { $0 == " " || $0 == "-" })
    return parts.joined(separator: "-")
}

func readFile(at path: String) -> String {
    let url = URL(fileURLWithPath: path)
    guard let data = try? Data(contentsOf: url),
          let text = String(data: data, encoding: .utf8) else {
        return ""
    }
    return text
}

func ensureDirectory(for path: String) {
    let url = URL(fileURLWithPath: path)
    let dir = url.deletingLastPathComponent()
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
}

// MARK: - Concepts

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

// MARK: - Concept map parsing

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

// MARK: - Examples

func languageCounts(for paths: [String]) -> [String: Int] {
    var counts: [String: Int] = [:]
    let map: [String: String] = [
        "swift": "swift",
        "sh": "bash",
        "bash": "bash",
        "zsh": "bash",
        "c": "c",
        "m": "c",
        "h": "c",
        "py": "python",
        "rs": "rust",
        "md": "markdown",
        "txt": "text"
    ]
    for path in paths {
        let ext = URL(fileURLWithPath: path).pathExtension.lowercased()
        guard let lang = map[ext] else { continue }
        counts[lang, default: 0] += 1
    }
    return counts
}

func dominantLanguage(for paths: [String]) -> String {
    let counts = languageCounts(for: paths)
    guard let (lang, count) = counts.max(by: { $0.value < $1.value }) else {
        return "mixed"
    }
    let ties = counts.filter { $0.value == count }
    if ties.count > 1 {
        return "mixed"
    }
    return lang
}

func firstMarkdownLine(in directory: URL) -> String? {
    guard let enumerator = FileManager.default.enumerator(at: directory, includingPropertiesForKeys: nil) else {
        return nil
    }
    for case let fileURL as URL in enumerator {
        if fileURL.pathExtension.lowercased() == "md" {
            let lines = readFile(at: fileURL.path).split(separator: "\n")
            for raw in lines {
                let trimmed = raw.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty { continue }
                if trimmed.hasPrefix("#") {
                    return trimmed.trimmingCharacters(in: CharacterSet(charactersIn: "# ").union(.whitespaces))
                }
                return trimmed
            }
        }
    }
    return nil
}

func collectFiles(in directory: URL, base: URL) -> [String] {
    guard let enumerator = FileManager.default.enumerator(at: directory, includingPropertiesForKeys: [.isRegularFileKey]) else {
        return []
    }
    var results: [String] = []
    for case let fileURL as URL in enumerator {
        let values = try? fileURL.resourceValues(forKeys: [.isRegularFileKey])
        if values?.isRegularFile == true {
            let relative = fileURL.path.replacingOccurrences(of: base.path + "/", with: "")
            results.append(relative)
        }
    }
    return results.sorted()
}

func exampleEntries(base: URL) -> [ExampleCode] {
    let examplesDir = base.appendingPathComponent("book/examples")
    guard let items = try? FileManager.default.contentsOfDirectory(at: examplesDir, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]) else {
        return []
    }
    var entries: [ExampleCode] = []
    for item in items {
        let values = try? item.resourceValues(forKeys: [.isDirectoryKey])
        guard values?.isDirectory == true else { continue }
        let dirName = item.lastPathComponent
        if dirName.lowercased() == "agents.md" { continue }
        let files = collectFiles(in: item, base: base)
        let lang = dominantLanguage(for: files)
        let desc = firstMarkdownLine(in: item) ?? "Example \(dirName)"
        let tags = dirName.split(whereSeparator: { $0 == "-" || $0 == "_" }).map { String($0) }
        let entry = ExampleCode(
            id: slugify(dirName),
            paths: files,
            language: lang,
            description: desc,
            chapterBindings: [],
            tags: tags
        )
        entries.append(entry)
    }
    return entries.sorted(by: { $0.id < $1.id })
}

// MARK: - Text regions

func textRegions(base: URL) -> [TextRegion] {
    let chaptersDir = base.appendingPathComponent("book/chapters")
    guard let items = try? FileManager.default.contentsOfDirectory(at: chaptersDir, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]) else {
        return []
    }
    var regions: [TextRegion] = []
    for dir in items {
        let values = try? dir.resourceValues(forKeys: [.isDirectoryKey])
        guard values?.isDirectory == true else { continue }
        let name = dir.lastPathComponent
        guard name.lowercased().hasPrefix("chapter") else { continue }
        let parts = name.split(separator: "-")
        guard let numPart = parts.first else { continue }
        let digits = numPart.drop { !$0.isNumber }
        let chapterNumber = Int(digits) ?? 0
        let title = parts.dropFirst().joined(separator: " ")
        let regionTitle = title.isEmpty ? "Chapter \(chapterNumber)" : "Chapter \(chapterNumber) \(title)"
        let mdFiles = collectFiles(in: dir, base: base).filter { $0.hasSuffix(".md") }
        guard let firstFile = mdFiles.first else { continue }
        regions.append(
            TextRegion(
                id: String(format: "ch%02d.0", chapterNumber),
                chapterNumber: chapterNumber,
                subchapterNumber: 0,
                title: regionTitle,
                file: firstFile,
                anchorID: slugify(regionTitle)
            )
        )
    }
    return regions.sorted(by: { $0.id < $1.id })
}

// MARK: - Binding stub

func conceptTextBindings() -> [ConceptTextBinding] {
    return []
}

// MARK: - Write JSON

func writeJSON<T: Encodable>(_ value: T, to path: String) {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    do {
        let data = try encoder.encode(value)
        ensureDirectory(for: path)
        try data.write(to: URL(fileURLWithPath: path))
    } catch {
        fputs("Failed to write \(path): \(error)\n", stderr)
    }
}

// MARK: - Main

func main() {
    let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    let concepts = parseConcepts(
        conceptsPath: root.appendingPathComponent("substrate/Concepts.md").path,
        inventoryPath: root.appendingPathComponent("book/graph/concepts/CONCEPT_INVENTORY.md").path
    )
    let conceptDetails = parseConceptDetails(
        mapPath: root.appendingPathComponent("book/graph/concepts/validation/Concept_map.md").path,
        concepts: concepts
    )
    let strategyList = strategies(concepts: concepts)
    let examples = exampleEntries(base: root)
    let regions = textRegions(base: root)
    let bindings = conceptTextBindings()

    writeJSON(concepts, to: root.appendingPathComponent("book/graph/concepts/concepts.json").path)
    writeJSON(conceptDetails, to: root.appendingPathComponent("book/graph/concepts/concept_map.json").path)
    writeJSON(strategyList, to: root.appendingPathComponent("book/graph/concepts/validation/strategies.json").path)
    writeJSON(examples, to: root.appendingPathComponent("book/examples/examples.json").path)
    writeJSON(regions, to: root.appendingPathComponent("book/graph/regions/text_regions.json").path)
    writeJSON(bindings, to: root.appendingPathComponent("book/graph/concepts/concept_text_map.json").path)
}

main()
