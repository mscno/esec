import AppKit
import EsecCore
import SwiftUI

@MainActor
final class SecretFileWindow: NSWindowController, NSWindowDelegate {
    let model: SecretDocumentStore
    var onClose: (() -> Void)?

    init(path: String, cli: CLI) {
        model = SecretDocumentStore(path: path, cli: cli)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 800, height: 640),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = URL(fileURLWithPath: path).lastPathComponent + " — Esec"
        window.isReleasedWhenClosed = false
        window.isRestorable = false
        let hosting = NSHostingView(rootView: SecretFileView(model: model))
        hosting.sizingOptions = []
        window.contentView = hosting
        window.minSize = NSSize(width: 640, height: 440)
        window.setContentSize(NSSize(width: 800, height: 640))
        window.center()
        super.init(window: window)
        window.delegate = self
    }

    required init?(coder: NSCoder) { nil }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if model.saving { return false }
        guard model.dirty else { return true }
        let alert = NSAlert()
        alert.messageText = "Discard unsaved changes?"
        alert.informativeText = "The encrypted file still contains the last saved value."
        alert.addButton(withTitle: "Keep Editing")
        alert.addButton(withTitle: "Discard Changes")
        alert.beginSheetModal(for: sender) { [weak self] response in
            if response == .alertSecondButtonReturn {
                self?.model.lock()
                self?.close()
            }
        }
        return false
    }

    func windowWillClose(_ notification: Notification) {
        model.lock()
        onClose?()
    }
    func windowDidResignKey(_ notification: Notification) { model.hideAll() }
}

struct SecretFileView: View {
    @Bindable var model: SecretDocumentStore
    @State private var confirmReload = false

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if let issue = model.readIssue, !model.editing {
                VStack(alignment: .leading, spacing: 6) {
                    Label(issue.title, systemImage: "exclamationmark.triangle").font(.headline)
                    Text(issue.guidance)
                    Text(issue.message).font(.caption).textSelection(.enabled)
                }
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .foregroundStyle(.orange).padding()
                .background(.orange.opacity(0.08))
            }
            if model.loading {
                Spacer()
                ProgressView("Decrypting securely…")
                Text("Approve the read if macOS or your security key asks.")
                    .font(.callout).foregroundStyle(.secondary).padding(.top, 8)
                Spacer()
            } else if let document = model.document {
                if model.changedOnDisk {
                    HStack {
                        Label("This file changed on disk. Reload before editing.", systemImage: "arrow.triangle.2.circlepath")
                        Spacer()
                        Button("Reload") { reload() }
                    }.font(.callout).padding().background(.orange.opacity(0.12))
                }
                HStack {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("Filter key names", text: $model.search).textFieldStyle(.plain)
                    Text("\(model.visibleValues.count) of \(document.values.count)").foregroundStyle(.secondary)
                }.padding(12)
                Divider()
                if document.values.isEmpty {
                    ContentUnavailableView("No secret values yet", systemImage: "key", description: Text("Add a key to this file to get started."))
                } else if model.visibleValues.isEmpty {
                    ContentUnavailableView.search(text: model.search)
                } else {
                    ScrollView {
                        LazyVStack(spacing: 6) {
                            ForEach(model.visibleValues) { entry in secretRow(entry) }
                        }.padding(16)
                    }
                }
            } else {
                ContentUnavailableView {
                    Label(model.readIssue?.title ?? "Secrets are locked", systemImage: "lock.doc")
                } description: {
                    Text(model.readIssue == nil ? "Open this file to decrypt its values in memory." : "No values were decrypted. The file on disk is unchanged.")
                } actions: {
                    Button(model.readIssue == nil ? "Decrypt and Show" : "Retry") { Task { await model.load() } }.buttonStyle(.borderedProminent)
                }
            }
            Divider()
            HStack {
                Label(model.notice ?? (model.document == nil ? "No decrypted values · File unchanged" : "Decrypted in memory · Saved encrypted"), systemImage: "lock.shield")
                Spacer()
                Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: model.path)]) }
                    .buttonStyle(.link)
            }.font(.caption).foregroundStyle(.secondary).padding(12)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(Color(nsColor: .windowBackgroundColor))
        .sheet(isPresented: $model.editing, onDismiss: { model.cancelEdit() }) {
            SecretValueEditor(model: model)
        }
        .confirmationDialog("Discard changes and reload?", isPresented: $confirmReload) {
            Button("Discard and Reload", role: .destructive) { Task { await model.load() } }
        }
        .task {
            await model.load()
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                if Task.isCancelled { break }
                model.checkForChanges()
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in model.hideAll() }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.willSleepNotification)) { _ in model.lock() }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.screensDidSleepNotification)) { _ in model.lock() }
        .onDisappear { model.lock() }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Image(systemName: "doc.text.magnifyingglass").font(.largeTitle).foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 10) {
                        Text(URL(fileURLWithPath: model.path).lastPathComponent).font(.title2.bold())
                        if let document = model.document {
                            SecretDecryptionBadge(info: document.decryption)
                        }
                    }
                    if let file = model.document?.file {
                        Text("\(file.project ?? "") · \(file.env.isEmpty ? "default" : file.env) · \(file.format)")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    Text((model.path as NSString).abbreviatingWithTildeInPath)
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).help(model.path)
                }
                Spacer()
            }
            HStack {
                Button(model.allRevealed ? "Hide All" : "Show All", systemImage: model.allRevealed ? "eye.slash" : "eye") { model.toggleAll() }
                    .disabled(model.document?.values.isEmpty != false)
                Button("Reload", systemImage: "arrow.clockwise") { reload() }
                    .disabled(model.loading || model.saving)
                Button("Lock", systemImage: "lock") { model.lock() }
                    .disabled(model.saving)
                Spacer()
                if model.document?.canAdd == true {
                    Button("Add Key", systemImage: "plus") { model.edit(nil) }
                        .disabled(model.changedOnDisk || model.saving)
                }
            }.buttonStyle(.bordered)
        }.padding(20)
    }

    private func secretRow(_ entry: SecretValue) -> some View {
        let visible = model.revealed.contains(entry.key)
        return HStack(spacing: 14) {
            Text(entry.key)
                .font(.system(.body, design: .monospaced).weight(.semibold))
                .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                .frame(width: 200, alignment: .leading)
                .help(entry.key)
            if visible {
                Text(entry.value.isEmpty ? "(empty value)" : entry.value.replacingOccurrences(of: "\n", with: " ↵ "))
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1).truncationMode(.tail).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                Text("••••••••••••••••").accessibilityLabel("Hidden secret")
                    .font(.system(.body, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            Button(visible ? "Hide" : "Show", systemImage: visible ? "eye.slash" : "eye") { model.toggle(entry.key) }
                .labelStyle(.iconOnly)
                .help(visible ? "Hide \(entry.key)" : "Show \(entry.key)")
            if entry.editable {
                Button("Edit", systemImage: "pencil") { model.edit(entry) }
                    .disabled(model.changedOnDisk)
            } else {
                Image(systemName: "lock").foregroundStyle(.secondary)
                    .help("Read only: metadata, array elements and complex key paths can be viewed here.")
            }
        }
        .buttonStyle(.borderless)
        .padding(.horizontal, 14).padding(.vertical, 12)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(.separator.opacity(0.5)))
        .privacySensitive()
    }

    private func reload() {
        if model.dirty { confirmReload = true } else { Task { await model.load() } }
    }
}

struct SecretValueEditor: View {
    @Bindable var model: SecretDocumentStore
    @State private var discard = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(model.adding ? "Add secret key" : "Edit secret value").font(.title2.bold())
            if model.adding {
                TextField("Key name", text: $model.draftKey, prompt: Text("API_KEY"))
                    .textFieldStyle(.roundedBorder)
            } else {
                Text(model.draftKey).font(.system(.body, design: .monospaced).bold())
            }
            HStack {
                Text("Value").font(.headline)
                Spacer()
                Toggle("Show value", isOn: $model.draftVisible).toggleStyle(.switch)
            }
            if model.draftVisible {
                TextEditor(text: $model.draftValue).font(.system(.body, design: .monospaced))
                    .frame(height: 160).border(.separator)
            } else {
                SecureField("Secret value", text: $model.draftValue).textFieldStyle(.roundedBorder)
                Text("Show the value to edit multiple lines. Empty values are allowed.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let error = model.error { Text(error).foregroundStyle(.red).textSelection(.enabled) }
            if model.changedOnDisk {
                Label("The file changed. Cancel and reload before saving.", systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
            }
            Text("Save encrypts this value before replacing the file. Your edit stays in memory until then.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Cancel") { if model.dirty { discard = true } else { model.cancelEdit() } }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                if model.saving { ProgressView().controlSize(.small) }
                Button("Save Encrypted") { Task { await model.save() } }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(!model.canSave)
            }
        }
        .padding(24).frame(width: 520)
        .disabled(model.saving)
        .interactiveDismissDisabled(model.dirty || model.saving)
        .privacySensitive()
        .confirmationDialog("Discard this edit?", isPresented: $discard) {
            Button("Discard Changes", role: .destructive) { model.cancelEdit() }
        }
    }
}
