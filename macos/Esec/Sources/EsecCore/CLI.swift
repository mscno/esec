import Foundation

/// One local esec process per operation. The app never calls esec-vault.
public struct CLI: Sendable {
    public let binary: URL
    public typealias PromptHandler = @Sendable (HardwarePrompt) async -> HardwareReply
    public init(binary: URL) { self.binary = binary }
    public static var environment: [String: String] {
        var env = ProcessInfo.processInfo.environment
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        env["PATH"] = ["/opt/homebrew/bin", "/usr/local/bin", home + "/go/bin", env["PATH"] ?? "/usr/bin:/bin"].joined(separator: ":")
        env["NO_COLOR"] = "1"
        return env
    }
    public static func locate() -> CLI? {
        var candidates: [String] = []
        if let p = ProcessInfo.processInfo.environment["ESEC_BIN"] { candidates.append(p) }
        if Bundle.main.bundleIdentifier == "com.mscno.esec", let url = Bundle.main.executableURL {
            candidates.append(url.deletingLastPathComponent().appendingPathComponent("esec").path)
        }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        candidates += [home + "/go/bin/esec", "/opt/homebrew/bin/esec", "/usr/local/bin/esec"]
        for dir in (environment["PATH"] ?? "").split(separator: ":") { candidates.append("\(dir)/esec") }
        return candidates.first(where: FileManager.default.isExecutableFile(atPath:)).map { CLI(binary: URL(fileURLWithPath: $0)) }
    }
    public struct Failure: Error, LocalizedError, Sendable {
        public let message: String
        public var errorDescription: String? { message }
    }
    public func run(_ args: [String], in directory: String? = nil, stdin: String? = nil, prompt: PromptHandler? = nil) async throws -> Data {
        let operation = Operation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    continuation.resume(with: Result { try execute(args, directory, stdin, prompt, operation) })
                }
            }
        } onCancel: { operation.cancel() }
    }
    private func execute(_ args: [String], _ directory: String?, _ input: String?, _ prompt: PromptHandler?, _ operation: Operation) throws -> Data {
        let process = Process(), output = Pipe(), errors = Pipe(), incoming = Pipe()
        process.executableURL = binary; process.arguments = args; process.environment = Self.environment
        if let directory { process.currentDirectoryURL = URL(fileURLWithPath: directory) }
        process.standardOutput = output; process.standardError = errors
        process.standardInput = (input != nil || prompt != nil) ? incoming : FileHandle.nullDevice
        try operation.start(process, incoming.fileHandleForWriting)
        defer { operation.finish(); try? incoming.fileHandleForWriting.close() }
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + 180)
        timer.setEventHandler { operation.cancel() }; timer.resume(); defer { timer.cancel() }
        let stderr = DataBox(), group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async { stderr.data = errors.fileHandleForReading.readDataToEndOfFile(); group.leave() }
        if let input {
            group.enter()
            DispatchQueue.global().async {
                try? incoming.fileHandleForWriting.write(contentsOf: Data(input.utf8))
                try? incoming.fileHandleForWriting.close(); group.leave()
            }
        }
        var result = Data()
        do {
            if let prompt { result = try readProtocol(output.fileHandleForReading, incoming.fileHandleForWriting, prompt, operation) }
            else { result = output.fileHandleForReading.readDataToEndOfFile() }
        } catch { operation.cancel(); group.wait(); process.waitUntilExit(); throw error }
        group.wait(); process.waitUntilExit()
        if operation.isCancelled { throw CancellationError() }
        guard process.terminationStatus == 0 else {
            // stdout might contain secret data from a failed command. Never put it in diagnostics.
            let message = String(decoding: stderr.data, as: UTF8.self).split(separator: "\n").last.map(String.init) ?? "Esec operation cancelled or failed"
            throw Failure(message: message)
        }
        return result
    }
    private func readProtocol(_ output: FileHandle, _ input: FileHandle, _ handler: @escaping PromptHandler, _ operation: Operation) throws -> Data {
        var pending = Data(), result: Data?
        while true {
            let chunk = output.availableData
            if chunk.isEmpty { break }
            pending.append(chunk)
            guard pending.count <= 20 * 1024 * 1024 else { throw Failure(message: "Esec response is too large") }
            while let newline = pending.firstIndex(of: 10) {
                let line = Data(pending[..<newline]); pending.removeSubrange(...newline)
                let frame = try JSON.decoder.decode(HardwarePrompt.self, from: line)
                if frame.type == "result" {
                    struct ResultFrame: Decodable { let document: SecretDocument }
                    _ = try JSON.decoder.decode(ResultFrame.self, from: line)
                    guard let object = try JSONSerialization.jsonObject(with: line) as? [String: Any], let document = object["document"] else { throw Failure(message: "Invalid Esec document") }
                    result = try JSONSerialization.data(withJSONObject: document)
                } else if ["message", "input", "confirm"].contains(frame.type) {
                    let done = DispatchSemaphore(value: 0)
                    let request = Task {
                        defer { done.signal() }
                        guard !Task.isCancelled, !operation.isCancelled else { return }
                        let reply = await handler(frame)
                        if frame.type != "message", !operation.isCancelled {
                            var data = (try? JSONEncoder().encode(reply)) ?? Data(); data.append(10)
                            try? input.write(contentsOf: data)
                        }
                    }
                    while done.wait(timeout: .now() + 0.1) == .timedOut {
                        if operation.isCancelled { request.cancel(); throw CancellationError() }
                    }
                } else { throw Failure(message: "Unsupported Esec response") }
            }
        }
        guard pending.isEmpty else { throw Failure(message: "Incomplete Esec response") }
        return result ?? Data()
    }
    public func files(in directory: String) async throws -> [SecretsFile] {
        try JSON.decoder.decode([SecretsFile].self, from: await run(["files", "--dir", directory, "--json"]))
    }
    public static func quote(_ text: String) -> String { "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    public static func cancelAll() { Operation.cancelAll() }
}
private final class DataBox: @unchecked Sendable { var data = Data() }
private final class Operation: @unchecked Sendable {
    private static let registry = Registry()
    private let lock = NSLock()
    private var process: Process?
    private var input: FileHandle?
    private var cancelled = false
    var isCancelled: Bool { lock.withLock { cancelled } }
    func start(_ process: Process, _ input: FileHandle) throws {
        try lock.withLock {
            if cancelled { throw CancellationError() }
            self.process = process; self.input = input; try process.run()
        }
        Self.registry.add(self)
    }
    func cancel() {
        lock.withLock { cancelled = true; try? input?.close(); if process?.isRunning == true { process?.terminate() } }
    }
    func finish() { Self.registry.remove(self) }
    static func cancelAll() { registry.all().forEach { $0.cancel() } }
    private final class Registry: @unchecked Sendable {
        let lock = NSLock(); var operations: [ObjectIdentifier: Operation] = [:]
        func add(_ value: Operation) { lock.withLock { operations[ObjectIdentifier(value)] = value } }
        func remove(_ value: Operation) { _ = lock.withLock { operations.removeValue(forKey: ObjectIdentifier(value)) } }
        func all() -> [Operation] { lock.withLock { Array(operations.values) } }
    }
}
