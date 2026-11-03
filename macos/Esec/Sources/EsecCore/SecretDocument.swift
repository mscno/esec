import Foundation

public struct SecretValue: Codable, Identifiable, Sendable, Equatable {
    public let key: String
    public var value: String
    public let editable: Bool
    public var id: String { key }

    public init(key: String, value: String, editable: Bool) {
        self.key = key
        self.value = value
        self.editable = editable
    }
}

/// Never persisted: only the selected file's window owns these values.
public struct SecretDocument: Decodable, Sendable {
    public let file: SecretsFile
    public var revision: String
    public var values: [SecretValue]
    public let decryption: SecretDecryption?

    public var canAdd: Bool { [".env", ".eyaml", ".eyml"].contains(file.format) }
}

/// Metadata from the successful read, never inferred from key availability.
public struct SecretDecryption: Decodable, Sendable, Equatable {
    public let source: String
    public let guardLevel: String

    enum CodingKeys: String, CodingKey {
        case source
        case guardLevel = "guard"
    }

    public var title: String {
        switch source {
        case "local_age": "Local age identity"
        case "local_key": "Local Esec key"
        case "sealed_identity", "workload_identity": "Local sealed key"
        case "workload_key": "Local deployment key"
        default: "Local decryption"
        }
    }
    public var symbol: String { source == "local_age" ? "key.horizontal" : "key" }
    public var explanation: String {
        "Last successful read: " + title + ". Esec decrypted this file locally in memory; the file stayed encrypted. For age access, the authorized recipient determines whether hardware touch is required."
    }
}

extension CLI {
    public func secretDocument(path: String, prompt: PromptHandler? = nil) async throws -> SecretDocument {
        // Unlike status JSON, a failed command must never be decoded as success.
        let data = try await run(["secrets", "show", "--file", path, "--json"] + (prompt == nil ? [] : ["--gui"]), prompt: prompt)
        return try JSON.decoder.decode(SecretDocument.self, from: data)
    }

    public func updateSecret(path: String, revision: String, key: String, value: String, create: Bool) async throws -> String {
        struct Update: Encodable {
            let revision: String
            let key: String
            let value: String
            let create: Bool
        }
        struct Saved: Decodable { let revision: String }
        let input = try JSONEncoder().encode(Update(revision: revision, key: key, value: value, create: create))
        let output = try await run(["secrets", "update", "--file", path], stdin: String(decoding: input, as: UTF8.self))
        return try JSON.decoder.decode(Saved.self, from: output).revision
    }
}
