import CryptoKit
import EsecCore
import Foundation
import Observation

struct SecretEnvironmentColumn: Identifiable {
    let env: String
    let files: [SecretsFile]
    var id: String { env }
    var title: String { env.isEmpty ? "default" : env }
}

struct ComparedSecret: Identifiable {
    let file: SecretsFile
    let entry: SecretValue
    var id: String { file.path + "\0" + entry.key }
}

@MainActor @Observable
final class SecretComparisonStore {
    let project: String
    let files: [SecretsFile]
    let cli: CLI
    var documents: [String: SecretDocument] = [:]
    var errors: [String: String] = [:]
    var revealed: Set<String> = []
    var changedPaths: Set<String> = []
    var search = ""
    var loadingPath: String?
    private var generation = UUID()
    private var pendingRead: Task<SecretDocument, Error>?
    private var revealIncoming = true

    init(project: String, files: [SecretsFile], cli: CLI) {
        self.project = project
        // A nested checkout may have been scanned through two roots.
        var seen: Set<String> = []
        self.files = files.filter { seen.insert($0.path).inserted }.sorted { $0.path < $1.path }
        self.cli = cli
    }

    var columns: [SecretEnvironmentColumn] {
        let grouped = Dictionary(grouping: files, by: \.env)
        return SecretEnvironmentOrder.sorted(Array(grouped.keys)).map { SecretEnvironmentColumn(env: $0, files: grouped[$0]!) }
    }
    var keys: [String] {
        // Unread files still contribute known keys, so a failed approval cannot
        // make an environment look as though a key is simply missing.
        var keys = Set(files.flatMap { documents[$0.path]?.values.map(\.key) ?? $0.keys ?? [] })
        if !search.isEmpty { keys = keys.filter { $0.localizedCaseInsensitiveContains(search) } }
        return keys.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
    }
    var loading: Bool { loadingPath != nil }
    var readIssues: [SecretReadIssue] { Array(Set(errors.values)).sorted().map(SecretReadIssue.init) }

    var allRevealed: Bool {
        let entries = allEntries
        return !entries.isEmpty && entries.allSatisfy { revealed.contains($0.id) }
    }
    private var allEntries: [ComparedSecret] {
        files.flatMap { file in (documents[file.path]?.values ?? []).map { ComparedSecret(file: file, entry: $0) } }
    }
    func values(for key: String, in column: SecretEnvironmentColumn) -> [ComparedSecret] {
        column.files.compactMap { file in
            guard let entry = documents[file.path]?.values.first(where: { $0.key == key }) else { return nil }
            return ComparedSecret(file: file, entry: entry)
        }
    }
    func incomplete(_ column: SecretEnvironmentColumn) -> Bool {
        column.files.contains { documents[$0.path] == nil }
    }
    func hasDifferentValues(_ key: String) -> Bool {
        // Only compare complete reads; locked columns do not imply a mismatch.
        let values = columns.flatMap { self.values(for: key, in: $0).map { $0.entry.value } }
        return Set(values).count > 1
    }
    func hideAll() { revealed = []; revealIncoming = false }
    func toggleAll() {
        if allRevealed { hideAll() }
        else { revealed = Set(allEntries.map(\.id)); revealIncoming = true }
    }
    func toggle(_ entry: ComparedSecret) {
        if revealed.contains(entry.id) { revealed.remove(entry.id) } else { revealed.insert(entry.id) }
    }

    func load(_ selected: [SecretsFile]? = nil) async {
        guard !loading else { return }
        if selected == nil { lock(); revealIncoming = true }
        let request = generation
        for file in selected ?? files {
            guard request == generation else { return }
            loadingPath = file.path
            errors[file.path] = nil
            do {
                // Sequential reads keep age hardware approval sheets orderly.
                let read = Task { try await cli.secretDocument(path: file.path, prompt: HardwareUI.respond) }
                pendingRead = read
                let document = try await read.value
                pendingRead = nil
                guard request == generation else { return }
                documents[file.path] = document
                changedPaths.remove(file.path)
                if revealIncoming {
                    for entry in document.values { revealed.insert(ComparedSecret(file: file, entry: entry).id) }
                }
            } catch {
                guard request == generation else { return }
                documents[file.path] = nil
                errors[file.path] = error.localizedDescription
            }
        }
        loadingPath = nil
    }

    func lock() {
        pendingRead?.cancel(); pendingRead = nil
        generation = UUID()
        documents = [:]; errors = [:]; revealed = []; changedPaths = []
        loadingPath = nil
    }

    func checkForChanges() {
        guard !loading else { return }
        for (path, document) in documents {
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { changedPaths.insert(path); continue }
            let revision = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            if revision != document.revision { changedPaths.insert(path) } else { changedPaths.remove(path) }
        }
    }
}
