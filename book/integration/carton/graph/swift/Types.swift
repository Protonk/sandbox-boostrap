import Foundation

// MARK: - Typealiases

public typealias ConceptID = String

// MARK: - Nodes

public struct Concept: Codable {
    public let id: ConceptID
    public let name: String
    public let anchorID: String
    public let clusterTags: [String]
    public let notes: String?
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
