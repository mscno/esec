import AppKit
import EsecCore
import SwiftUI

@MainActor
final class SecretComparisonWindow: NSWindowController, NSWindowDelegate {
    let model: SecretComparisonStore
    var onClose: (() -> Void)?

    init(project: Project, cli: CLI, openFile: @escaping (String) -> Void) {
        model = SecretComparisonStore(project: project.project, files: project.files ?? [], cli: cli)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1180, height: 660),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = project.project + " — Compare Environments"
        window.isReleasedWhenClosed = false
        window.isRestorable = false
        let hosting = NSHostingView(rootView: SecretComparisonView(model: model, openFile: openFile))
        hosting.sizingOptions = []
        window.contentView = hosting
        window.minSize = NSSize(width: 760, height: 440)
        window.setContentSize(NSSize(width: 1180, height: 660))
        window.center()
        super.init(window: window)
        window.delegate = self
    }
    required init?(coder: NSCoder) { nil }
    func windowWillClose(_ notification: Notification) { model.lock(); onClose?() }
    func windowDidResignKey(_ notification: Notification) { model.hideAll() }
}

struct SecretComparisonView: View {
    @Bindable var model: SecretComparisonStore
    let openFile: (String) -> Void
    private let keyWidth: CGFloat = 220
    private let valueWidth: CGFloat = 280

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Compare environments").font(.title2.bold())
                        Text(model.project).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button(model.allRevealed ? "Hide All" : "Show All", systemImage: model.allRevealed ? "eye.slash" : "eye") { model.toggleAll() }
                        .disabled(model.documents.isEmpty)
                    Button(model.documents.isEmpty ? "Decrypt and Show" : "Reload", systemImage: "arrow.clockwise") { Task { await model.load() } }
                        .disabled(model.loading)
                    Button("Lock", systemImage: "lock") { model.lock() }
                }
                HStack {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("Filter key names", text: $model.search).textFieldStyle(.plain)
                    Spacer()
                    Text("\(model.keys.count) keys · \(model.columns.count) environments · \(model.files.count) files")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }.padding(20)
            Divider()
            if !model.errors.isEmpty && !model.loading {
                VStack(alignment: .leading, spacing: 6) {
                    Label("\(model.errors.count) file(s) could not be decrypted", systemImage: "exclamationmark.triangle")
                        .font(.headline)
                    ForEach(Array(Set(model.readIssues.map(\.guidance))).sorted(), id: \.self) { Text($0) }
                }
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .foregroundStyle(.orange).padding(12).background(.orange.opacity(0.08))
            }
            if let path = model.loadingPath {
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Decrypting \(URL(fileURLWithPath: path).lastPathComponent)… Approve the read if asked.")
                    Spacer()
                    Text("\(model.documents.count) / \(model.files.count)")
                }.font(.callout).padding(12)
            }
            if !model.changedPaths.isEmpty {
                Label("\(model.changedPaths.count) file(s) changed on disk. Reload to compare the latest values.", systemImage: "arrow.triangle.2.circlepath")
                    .font(.callout).foregroundStyle(.orange).padding(10)
            }
            ScrollView([.horizontal, .vertical]) {
                LazyVStack(spacing: 0, pinnedViews: [.sectionHeaders]) {
                    Section {
                        ForEach(model.keys, id: \.self) { key in
                            HStack(alignment: .top, spacing: 0) {
                                HStack(spacing: 8) {
                                    Text(key).font(.system(.body, design: .monospaced).weight(.semibold))
                                        .lineLimit(1).truncationMode(.middle).textSelection(.enabled).help(key)
                                    Spacer(minLength: 0)
                                    if model.hasDifferentValues(key) {
                                        Text("≠").foregroundStyle(.secondary)
                                            .accessibilityLabel("Different values")
                                            .help("The loaded values differ across files or environments")
                                    }
                                }.padding(12).frame(width: keyWidth, alignment: .leading)
                                ForEach(model.columns) { column in
                                    cell(key, column: column)
                                        .padding(12).frame(width: valueWidth, alignment: .leading)
                                }
                            }
                            .background(Color(nsColor: .controlBackgroundColor))
                            Divider()
                        }
                    } header: {
                        HStack(alignment: .top, spacing: 0) {
                            Text("KEY").font(.caption.bold()).foregroundStyle(.secondary)
                                .padding(12).frame(width: keyWidth, alignment: .leading)
                            ForEach(model.columns) { column in columnHeader(column) }
                        }
                        .background(.regularMaterial)
                        .overlay(alignment: .bottom) { Divider() }
                    }
                }
                .frame(width: keyWidth + valueWidth * CGFloat(model.columns.count), alignment: .leading)
            }
            Divider()
            HStack {
                Label(model.documents.isEmpty ? "No decrypted values · Files unchanged" : "Decrypted in memory · Files stay encrypted", systemImage: "lock.shield")
                Spacer()
                Text("— missing key   ·   ≠ different values")
            }.font(.caption).foregroundStyle(.secondary).padding(12)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            await model.load()
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(3))
                if Task.isCancelled { break }
                model.checkForChanges()
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in model.hideAll() }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.willSleepNotification)) { _ in model.lock() }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.screensDidSleepNotification)) { _ in model.lock() }
        .onDisappear { model.lock() }
    }

    private func columnHeader(_ column: SecretEnvironmentColumn) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(column.title).font(.headline)
                Spacer()
                Menu {
                    ForEach(column.files) { file in
                        Button(file.path) { openFile(file.path) }
                    }
                } label: { Image(systemName: "doc.on.doc") }
                .menuStyle(.borderlessButton).fixedSize()
                .accessibilityLabel("Open \(column.title) file")
                .help("Open an individual secrets file")
            }
            ForEach(column.files) { file in
                HStack(spacing: 6) {
                    Button(URL(fileURLWithPath: file.path).lastPathComponent) { openFile(file.path) }
                        .buttonStyle(.link).font(.caption).lineLimit(1).truncationMode(.middle)
                        .help(file.path)
                    Spacer(minLength: 0)
                    if let document = model.documents[file.path] {
                        SecretDecryptionBadge(info: document.decryption)
                    }
                }
            }
            let failures = column.files.compactMap { model.errors[$0.path] }
            if !failures.isEmpty {
                ForEach(Array(Set(failures)).sorted(), id: \.self) { message in
                    Text(message).font(.caption).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                }
                Button("Retry \(failures.count) failed file(s)", systemImage: "exclamationmark.triangle") {
                    Task { await model.load(column.files.filter { model.errors[$0.path] != nil }) }
                }
                .buttonStyle(.borderless).foregroundStyle(.orange).font(.caption)
                .help(failures.joined(separator: "\n")).disabled(model.loading)
            }
        }.padding(12).frame(width: valueWidth, alignment: .leading)
    }

    private func cell(_ key: String, column: SecretEnvironmentColumn) -> some View {
        let entries = model.values(for: key, in: column)
        return VStack(alignment: .leading, spacing: 8) {
            ForEach(entries) { value in
                VStack(alignment: .leading, spacing: 4) {
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        if model.revealed.contains(value.id) {
                            Text(value.entry.value.isEmpty ? "(empty)" : value.entry.value.replacingOccurrences(of: "\n", with: " ↵ "))
                                .lineLimit(2).textSelection(.enabled)
                        } else {
                            Text("••••••••••••").accessibilityLabel("Hidden secret")
                        }
                        Spacer(minLength: 0)
                        Button(model.revealed.contains(value.id) ? "Hide" : "Show", systemImage: model.revealed.contains(value.id) ? "eye.slash" : "eye") {
                            model.toggle(value)
                        }.labelStyle(.iconOnly).buttonStyle(.borderless)
                    }.font(.system(.body, design: .monospaced))
                    if column.files.count > 1 {
                        Button((value.file.path as NSString).abbreviatingWithTildeInPath) { openFile(value.file.path) }
                            .font(.caption2).buttonStyle(.link).lineLimit(1).truncationMode(.middle)
                            .help(value.file.path)
                    }
                }
                .contextMenu { Button("Open File to Edit") { openFile(value.file.path) } }
            }
            if model.incomplete(column) {
                Text(model.loading ? "Loading…" : model.errors.isEmpty ? "Locked" : "Unavailable")
                    .font(.caption).foregroundStyle(.secondary)
            } else if entries.isEmpty {
                Text("—").foregroundStyle(.tertiary).help("This key is absent from this environment")
            }
        }.frame(maxWidth: .infinity, alignment: .leading).privacySensitive()
    }
}
