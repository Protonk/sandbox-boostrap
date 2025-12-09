import Foundation

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
