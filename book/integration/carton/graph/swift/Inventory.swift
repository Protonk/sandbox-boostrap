import Foundation

public enum InventoryKind: String, Codable {
    case tool
    case api
    case evidence
    case mapping
    case contract
    case test
}

public enum InventoryEdgeKind: String, Codable {
    case produces
    case consumes
    case guards
    case declares
}

public enum InventorySensitivity: String, Codable {
    case normal
    case contract
}

public struct InventoryArtifact: Codable {
    public let id: String
    public let path: String
    public let kind: InventoryKind
    public let sensitivity: InventorySensitivity
    public let digestMode: String
    public let role: String?

    enum CodingKeys: String, CodingKey {
        case id
        case path
        case kind
        case sensitivity
        case digestMode = "digest_mode"
        case role
    }
}

public struct InventoryEdge: Codable {
    public let from: String
    public let to: String
    public let kind: InventoryEdgeKind
}

public struct InventoryMetadata: Codable {
    public let worldID: String?
    public let generatedBy: String?
    public let inputs: [String]?

    enum CodingKeys: String, CodingKey {
        case worldID = "world_id"
        case generatedBy = "generated_by"
        case inputs
    }
}

public struct InventoryGraph: Codable {
    public let schemaVersion: String
    public let worldID: String
    public let metadata: InventoryMetadata?
    public let artifacts: [InventoryArtifact]
    public let edges: [InventoryEdge]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case worldID = "world_id"
        case metadata
        case artifacts
        case edges
    }
}

func loadInventoryGraph(at path: String) -> InventoryGraph? {
    let url = URL(fileURLWithPath: path)
    guard let data = try? Data(contentsOf: url) else { return nil }
    return try? JSONDecoder().decode(InventoryGraph.self, from: data)
}

func inventoryValidation(graph: InventoryGraph?) -> (errors: [String], warnings: [String]) {
    guard let graph = graph else {
        return ([], ["inventory graph not found or unreadable"])
    }

    var errors: [String] = []
    var warnings: [String] = []

    let contractArtifacts = graph.artifacts.filter { $0.sensitivity == .contract }
    for artifact in contractArtifacts {
        let lower = artifact.path.lowercased()
        if lower.contains("spec.") == false && lower.contains("schema.") == false {
            warnings.append("contract artifact missing spec/schema token: \(artifact.path)")
        }
    }

    let guardEdges = Set(graph.edges.filter { $0.kind == .guards }.map { $0.from })
    let mappingArtifacts = graph.artifacts.filter { $0.kind == .mapping }
    let unguarded = mappingArtifacts.filter { guardEdges.contains($0.id) == false }
    if unguarded.isEmpty == false {
        warnings.append("unguarded mapping artifacts in inventory graph: \(unguarded.count)")
    }

    if graph.artifacts.isEmpty {
        errors.append("inventory graph has no artifacts")
    }
    if graph.edges.isEmpty {
        warnings.append("inventory graph has no edges")
    }

    return (errors, warnings)
}
