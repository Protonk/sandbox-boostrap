import Foundation

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
