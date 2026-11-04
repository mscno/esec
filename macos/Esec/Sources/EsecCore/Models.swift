import Foundation

public struct SecretsFile: Codable, Hashable, Sendable, Identifiable {
    public let path: String
    public let format: String
    public let env: String
    public let project: String?
    public let root: String?
    public let publicKey: String?
    public let keys: [String]?
    public let plain: [String]?
    public var id: String { path }
    enum CodingKeys: String, CodingKey {
        case path, format, env, project, root, keys, plain
        case publicKey = "public_key"
    }
}
public struct Project: Identifiable, Sendable {
    public let project: String
    public let path: String
    public let files: [SecretsFile]?
    public var id: String { path }
    public init(project: String, path: String, files: [SecretsFile]) {
        self.project = project; self.path = path; self.files = files
    }
}
public enum JSON { public static let decoder = JSONDecoder() }

public struct SecretReadIssue: Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var title: String { "Could not decrypt this file" }
    public var guidance: String {
        if message.contains("legacy_guard_requires_migration") { return "This environment needs offline migration. Supply its recovery key or an authorized age identity to esec adopt, then reopen it here." }
        if message.localizedCaseInsensitiveContains("yubikey") { return "Connect the configured YubiKey, install age-plugin-yubikey, and approve its PIN/touch prompt." }
        return "Check your local Esec identity configuration and the error below, then retry."
    }
}
public struct HardwarePrompt: Decodable, Sendable {
    public let type: String
    public let id: Int?
    public let plugin: String?
    public let message: String?
    public let secret: Bool?
    public let yes: String?
    public let no: String?
}
public struct HardwareReply: Encodable, Sendable {
    public let id: Int
    public let value: String
    public let confirmed: Bool
    public let cancelled: Bool
    public init(id: Int, value: String = "", confirmed: Bool = false, cancelled: Bool = false) {
        self.id = id; self.value = value; self.confirmed = confirmed; self.cancelled = cancelled
    }
}
