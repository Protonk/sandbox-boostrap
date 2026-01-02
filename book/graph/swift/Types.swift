import Foundation

// MARK: - Typealiases

public typealias ConceptID = String
public typealias ValidationID = String
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

public struct RuntimeProfile: Codable {
    public let profile_id: String
    public let status: String
    public let profile_path: String?
    public let trace_path: String?
}

public struct RuntimeMetadata: Codable {
    public let host: String?
    public let baseline: String?
    public let profile_format_variant: String?
    public let sip_status: String?
}

public struct RuntimeExpectations: Codable {
    public let metadata: RuntimeMetadata?
    public let profiles: [RuntimeProfile]
}

public struct ValidationReport: Codable {
    public let errors: [String]
    public let warnings: [String]
    public let checked: [String]
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
