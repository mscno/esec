@testable import EsecUI
import EsecCore
import Foundation
import Testing

@MainActor
private func secretFixture(failSave: Bool = false, delay: Bool = false) throws -> (SecretDocumentStore, URL) {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("esec-secret-test-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let fixture = #"{"file":{"path":"/example/.env.dev","format":".env","env":"dev","project":"acme/app"},"revision":"before","decryption":{"source":"local_key","guard":"none"},"values":[{"key":"API_KEY","value":"original","editable":true},{"key":"MULTILINE","value":"first\nsecond\n","editable":true}]}"#
    try ("{\"type\":\"result\",\"document\":" + fixture + "}\n").write(to: dir.appendingPathComponent("document.json"), atomically: true, encoding: .utf8)
    let script = """
    #!/bin/sh
    case "$1 $2" in
    'secrets show') \(delay ? "sleep 0.2" : ":"); cat \(CLI.quote(dir.appendingPathComponent("document.json").path)) ;;
    'secrets update')
      printf '%s\\n' "$*" > \(CLI.quote(dir.appendingPathComponent("args").path))
      cat > \(CLI.quote(dir.appendingPathComponent("input").path))
      \(failSave ? "echo 'file changed on disk' >&2; exit 1" : "printf '%s' '{\"revision\":\"after\"}'") ;;
    *) exit 1 ;;
    esac
    """
    let executable = dir.appendingPathComponent("esec")
    try script.write(to: executable, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
    let model = SecretDocumentStore(path: dir.appendingPathComponent(".env.dev").path, cli: CLI(binary: executable))
    return (model, dir)
}

@Test @MainActor func secretWindowShowsValuesByDefaultAndCanHideThem() async throws {
    let (model, dir) = try secretFixture()
    defer { try? FileManager.default.removeItem(at: dir) }
    await model.load()
    #expect(model.document?.values.count == 2)
    #expect(model.allRevealed)
    model.hideAll()
    model.toggle("API_KEY")
    #expect(model.revealed == ["API_KEY"])
    model.toggleAll()
    #expect(model.allRevealed)
    model.toggleAll()
    #expect(model.revealed.isEmpty)
    model.search = "multi"
    #expect(model.visibleValues.map(\.key) == ["MULTILINE"])
    model.search = "original"
    #expect(model.visibleValues.isEmpty) // search never inspects secret values
    model.edit(model.document?.values.first)
    model.draftValue = "unsaved"
    model.lock()
    #expect(model.document == nil)
    #expect(model.draftValue.isEmpty)
    #expect(!model.editing)
}

@Test @MainActor func secretSaveUsesStdinPreservesMultilineAndRemasks() async throws {
    let (model, dir) = try secretFixture()
    defer { try? FileManager.default.removeItem(at: dir) }
    await model.load()
    model.toggleAll()
    model.edit(model.document?.values.first)
    let value = "first\nsecond ' $VALUE \\ 🗝\n"
    model.draftValue = value
    await model.save()
    #expect(model.error == nil)
    #expect(model.document?.revision == "after")
    #expect(model.document?.decryption?.source == "local_key") // metadata describes the last read
    #expect(model.document?.values.first?.value == value)
    #expect(!model.revealed.contains("API_KEY"))
    #expect(model.draftValue.isEmpty)
    let data = try Data(contentsOf: dir.appendingPathComponent("input"))
    let payload = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    #expect(payload["value"] as? String == value)
    #expect(payload["revision"] as? String == "before")
    let args = try String(contentsOf: dir.appendingPathComponent("args"), encoding: .utf8)
    #expect(!args.contains("$VALUE"))
    #expect(!args.contains("API_KEY"))
}

@Test @MainActor func failedSecretSaveKeepsTheDraft() async throws {
    let (model, dir) = try secretFixture(failSave: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    await model.load()
    model.edit(model.document?.values.first)
    model.draftValue = ""
    #expect(model.canSave)
    await model.save()
    #expect(model.editing)
    #expect(model.draftValue == "")
    #expect(model.document?.revision == "before")
    #expect(model.document?.values.first?.value == "original")
    #expect(model.error?.contains("file changed") == true)
}

@Test @MainActor func lockingDuringDecryptionDoesNotRestoreValues() async throws {
    let (model, dir) = try secretFixture(delay: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let pending = Task { await model.load() }
    while !model.loading { await Task.yield() }
    model.lock()
    await pending.value
    #expect(model.document == nil)
    #expect(model.revealed.isEmpty)
    #expect(!model.loading)
}
