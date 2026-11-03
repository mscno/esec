import CryptoKit
import EsecCore
import Foundation
import Observation

@MainActor @Observable
final class SecretDocumentStore {
    let path: String
    let cli: CLI
    var document: SecretDocument?
    var revealed: Set<String> = []
    var search = ""
    var loading = false
    var saving = false
    var error: String?
    var notice: String?
    var changedOnDisk = false
    var editing = false
    var adding = false
    var draftKey = ""
    var draftValue = ""
    var draftVisible = false
    private var originalValue = ""
    private var generation = UUID()
    private var pendingRead: Task<SecretDocument, Error>?

    init(path: String, cli: CLI) { self.path = path; self.cli = cli }

    var visibleValues: [SecretValue] {
        (document?.values ?? []).filter { search.isEmpty || $0.key.localizedCaseInsensitiveContains(search) }
    }
    var readIssue: SecretReadIssue? { error.map(SecretReadIssue.init) }

    var allRevealed: Bool {
        guard let values = document?.values, !values.isEmpty else { return false }
        return values.allSatisfy { revealed.contains($0.key) }
    }
    var dirty: Bool { editing && (adding ? !draftKey.isEmpty || !draftValue.isEmpty : draftValue != originalValue) }
    var canSave: Bool {
        guard editing, !saving, !changedOnDisk, !draftKey.isEmpty else { return false }
        if adding {
            return draftKey.range(of: "^[A-Za-z][A-Za-z0-9_]*$", options: .regularExpression) != nil
                && !(document?.values.contains { $0.key == draftKey } ?? false)
        }
        return dirty
    }

    func load() async {
        guard !loading, !saving else { return }
        lock()
        loading = true
        let request = generation
        do {
            let read = Task { try await cli.secretDocument(path: path, prompt: HardwareUI.respond) }
            pendingRead = read
            let next = try await read.value
            pendingRead = nil
            guard request == generation else { return }
            document = next
            revealed = Set(next.values.map(\.key))
            loading = false
        } catch {
            guard request == generation else { return }
            self.error = error.localizedDescription
            loading = false
        }
    }

    func hideAll() { revealed = []; draftVisible = false }
    func toggleAll() {
        if allRevealed { hideAll() }
        else { revealed = Set(document?.values.map(\.key) ?? []) }
    }
    func toggle(_ key: String) {
        if revealed.contains(key) { revealed.remove(key) } else { revealed.insert(key) }
    }
    func edit(_ entry: SecretValue?) {
        adding = entry == nil
        draftKey = entry?.key ?? ""
        draftValue = entry?.value ?? ""
        originalValue = draftValue
        draftVisible = false
        error = nil
        editing = true
    }
    func cancelEdit() {
        editing = false
        draftKey = ""; draftValue = ""; originalValue = ""; draftVisible = false
    }
    func save() async {
        guard let current = document, canSave else { return }
        saving = true
        error = nil
        let request = generation
        let key = draftKey, value = draftValue, create = adding
        do {
            let revision = try await cli.updateSecret(path: path, revision: current.revision, key: key, value: value, create: create)
            guard request == generation else { return }
            document?.revision = revision
            if create {
                document?.values.append(SecretValue(key: key, value: value, editable: true))
                document?.values.sort { $0.key < $1.key }
            } else if let index = document?.values.firstIndex(where: { $0.key == key }) {
                document?.values[index].value = value
            }
            revealed.remove(key)
            saving = false
            notice = "Saved encrypted · \(key)"
            cancelEdit()
            checkForChanges()
        } catch {
            guard request == generation else { return }
            saving = false
            self.error = error.localizedDescription
            checkForChanges()
        }
    }

    /// Clear owned references; Swift String does not promise secure memory erasure.
    func lock() {
        pendingRead?.cancel(); pendingRead = nil
        generation = UUID()
        document = nil
        hideAll()
        cancelEdit()
        loading = false; saving = false; changedOnDisk = false
        error = nil; notice = nil; search = ""
    }

    /// Only ciphertext is read here; polling never requests another decryption.
    func checkForChanges() {
        guard let document, !loading, !saving else { return }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            changedOnDisk = true
            return
        }
        let revision = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        changedOnDisk = revision != document.revision
    }
}
