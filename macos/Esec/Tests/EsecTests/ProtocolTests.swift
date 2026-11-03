import EsecCore
import Foundation
import Testing

private func protocolFixture(_ script: String) throws -> (CLI, URL) {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("esec-protocol-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let path = dir.appendingPathComponent("esec")
    try ("#!/bin/sh\n" + script).write(to: path, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: path.path)
    return (CLI(binary: path), dir)
}
private let resultLine = #"{"type":"result","document":{"file":{"path":"/fake/.env.dev","format":".env","env":"dev"},"revision":"test","values":[]}}"#
@Test func hardwareReplyUsesPipeAndNeverArguments() async throws {
    let (cli, dir) = try protocolFixture("""
    printf '%s\\n' '{"type":"input","id":1,"plugin":"yubikey","message":"PIN","secret":true}'
    IFS= read -r reply
    printf '%s' "$reply" > reply.json
    printf '%s' "$*" > arguments.txt
    printf '%s\\n' '\(resultLine)'
    """)
    defer { try? FileManager.default.removeItem(at: dir) }
    let data = try await cli.run(["secrets", "show", "--gui"], in: dir.path, prompt: { p in
        #expect(p.secret == true)
        return HardwareReply(id: p.id ?? 0, value: "synthetic-pin")
    })
    _ = try JSON.decoder.decode(SecretDocument.self, from: data)
    let reply = try String(contentsOf: dir.appendingPathComponent("reply.json"), encoding: .utf8)
    let arguments = try String(contentsOf: dir.appendingPathComponent("arguments.txt"), encoding: .utf8)
    #expect(reply.contains("synthetic-pin")); #expect(!arguments.contains("synthetic-pin"))
}
private actor PromptProbe {
    var entered = false
    var cancelled = false
    func respond(_ p: HardwarePrompt) async -> HardwareReply {
        entered = true
        do { try await Task.sleep(for: .seconds(10)) } catch { cancelled = true }
        return HardwareReply(id: p.id ?? 0, cancelled: true)
    }
}
@Test func cancellingAReadCancelsItsPendingPrompt() async throws {
    let (cli, dir) = try protocolFixture("""
    printf '%s\\n' '{"type":"input","id":1,"plugin":"yubikey","message":"PIN","secret":true}'
    IFS= read -r reply
    """)
    defer { try? FileManager.default.removeItem(at: dir) }
    let probe = PromptProbe()
    let read = Task { try await cli.run(["secrets", "show", "--gui"], prompt: { await probe.respond($0) }) }
    for _ in 0..<200 { if await probe.entered { break }; try await Task.sleep(for: .milliseconds(10)) }
    #expect(await probe.entered)
    read.cancel()
    do { _ = try await read.value; Issue.record("Cancelled read returned data") } catch {}
    for _ in 0..<100 { if await probe.cancelled { break }; try await Task.sleep(for: .milliseconds(10)) }
    #expect(await probe.cancelled)
}
@Test func failedReadsDoNotExposeStdoutAsDiagnostics() async throws {
    let (cli, dir) = try protocolFixture("printf 'synthetic-secret-output'; echo 'read failed' >&2; exit 1\n")
    defer { try? FileManager.default.removeItem(at: dir) }
    do { _ = try await cli.run(["secrets", "show"]); Issue.record("Failed command accepted") }
    catch { #expect(!error.localizedDescription.contains("synthetic-secret-output")) }
}
