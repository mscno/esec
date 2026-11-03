import AppKit
import EsecCore

enum HardwareUI {
    @MainActor static func respond(_ prompt: HardwarePrompt) async -> HardwareReply {
        let cancelled = HardwareReply(id: prompt.id ?? 0, cancelled: true)
        guard !Task.isCancelled else { return cancelled }
        guard prompt.type != "message" else { return HardwareReply(id: prompt.id ?? 0) }
        let session = PromptSession(prompt)
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if Task.isCancelled { continuation.resume(returning: cancelled) }
                else { session.enqueue(continuation) }
            }
        } onCancel: { Task { @MainActor in session.cancel() } }
    }
}

/// Serialize prompts across windows and remove both queued and active prompts on cancellation.
@MainActor private final class PromptSession {
    private static var queue: [PromptSession] = []
    private static var active: PromptSession?
    private let prompt: HardwarePrompt
    private let alert = NSAlert()
    private var field: NSTextField?
    private var continuation: CheckedContinuation<HardwareReply, Never>?
    private var cancelled = false
    init(_ prompt: HardwarePrompt) { self.prompt = prompt }
    func enqueue(_ continuation: CheckedContinuation<HardwareReply, Never>) {
        self.continuation = continuation
        if cancelled { finish(.abort); return }
        Self.queue.append(self); Self.advance()
    }
    private static func advance() {
        guard active == nil, !queue.isEmpty else { return }
        let next = queue.removeFirst(); active = next; next.show()
    }
    private func show() {
        guard !cancelled, let parent = NSApp.windows.first(where: { $0.isVisible && $0.sheetParent == nil && $0.attachedSheet == nil && !($0 is NSPanel) }) else { finish(.abort); return }
        alert.messageText = "Esec · \(prompt.plugin ?? "age")"
        alert.informativeText = prompt.message ?? "Approve this local decryption."
        alert.addButton(withTitle: prompt.type == "confirm" ? (prompt.yes ?? "Approve") : "Continue")
        alert.addButton(withTitle: "Cancel")
        if prompt.type == "input" {
            let input: NSTextField = prompt.secret == true ? NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 26)) : NSTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 26))
            input.placeholderString = prompt.secret == true ? "PIN or secret" : "Value"
            alert.accessoryView = input; alert.window.initialFirstResponder = input; field = input
        }
        NSApp.activate()
        alert.beginSheetModal(for: parent) { [weak self] response in self?.finish(response) }
    }
    func cancel() {
        cancelled = true
        Self.queue.removeAll { $0 === self }
        if let parent = alert.window.sheetParent { parent.endSheet(alert.window, returnCode: .abort) }
        alert.window.orderOut(nil)
        finish(.abort)
    }
    private func finish(_ response: NSApplication.ModalResponse) {
        guard let continuation else { return }
        self.continuation = nil
        let accepted = !cancelled && response == .alertFirstButtonReturn
        let reply = HardwareReply(id: prompt.id ?? 0, value: accepted ? (field?.stringValue ?? "") : "", confirmed: accepted, cancelled: !accepted)
        field?.stringValue = ""
        if Self.active === self { Self.active = nil }
        continuation.resume(returning: reply)
        Self.advance()
    }
}
