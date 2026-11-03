import AppKit
import EsecCore
import SwiftUI

public enum EsecApplication { @MainActor public static func main() { EsecApp.main() } }
struct EsecApp: App {
    @State private var store = Store.shared
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    var body: some Scene {
        Window("Esec", id: "main") {
            MainView().environment(store).frame(minWidth: 850, minHeight: 520).task { store.start() }
        }.commands {
            CommandGroup(replacing: .newItem) {
                Button("Open Secrets File…") { store.chooseSecretFile() }.keyboardShortcut("o")
                Button("Add Project Folder…") { store.chooseFolder() }.keyboardShortcut("o", modifiers: [.command, .shift])
                Button("Refresh") { Task { await store.refresh() } }.keyboardShortcut("r")
                Button("Lock All Windows") { store.lockAll() }.keyboardShortcut("l", modifiers: [.command, .shift])
            }
        }
        MenuBarExtra { MenuContent().environment(store) } label: { Image(systemName: "key.horizontal") }
    }
}
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_: Notification) {
        if Bundle.main.bundleIdentifier == nil { NSApp.setActivationPolicy(.accessory) }
        Store.shared.start()
    }
    func applicationWillTerminate(_: Notification) { Store.shared.lockAll() }
    func applicationShouldTerminateAfterLastWindowClosed(_: NSApplication) -> Bool { false }
    func application(_ application: NSApplication, open urls: [URL]) { urls.filter(\.isFileURL).forEach { Store.shared.openSecretFile($0.path) } }
}
struct MenuContent: View {
    @Environment(Store.self) private var store
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        Text("\(store.projects.count) local projects")
        Button("Open Esec") { openWindow(id: "main"); NSApp.activate() }
        Button("Open Secrets File…") { store.chooseSecretFile() }
        Button("Add Project Folder…") { store.chooseFolder() }
        Button("Lock All Windows") { store.lockAll() }
        Divider()
        Toggle("Open Esec at Login", isOn: Binding(get: { store.opensAtLogin }, set: { store.opensAtLogin = $0 }))
        Button("Quit Esec") { NSApp.terminate(nil) }
    }
}
struct MainView: View {
    @Environment(Store.self) private var store
    @State private var selection: String?
    var body: some View {
        @Bindable var store = store
        NavigationSplitView {
            List(selection: $selection) {
                Label("This Mac", systemImage: "desktopcomputer").tag("overview")
                Section("Projects") {
                    ForEach(store.filteredProjects) { project in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(project.project)
                            Text((project.path as NSString).abbreviatingWithTildeInPath).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                        }.tag(project.id)
                    }
                }
            }.searchable(text: $store.search, placement: .sidebar, prompt: "Projects and paths")
                .navigationSplitViewColumnWidth(min: 220, ideal: 280)
        } detail: {
            if let project = store.projects.first(where: { $0.id == selection }) { ProjectDetail(project: project) }
            else { overview }
        }.toolbar {
            Button("Open File", systemImage: "doc.text.magnifyingglass") { store.chooseSecretFile() }
            Button("Add Folder", systemImage: "folder.badge.plus") { store.chooseFolder() }
            Button("Refresh", systemImage: "arrow.clockwise") { Task { await store.refresh() } }.disabled(store.refreshing)
            if store.refreshing { ProgressView().controlSize(.small) }
        }.safeAreaInset(edge: .bottom) {
            if !store.errors.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(store.errors.keys.sorted(), id: \.self) { key in Text("\(key): \(store.errors[key] ?? "")").font(.caption).textSelection(.enabled) }
                }.frame(maxWidth: .infinity, alignment: .leading).padding(12).background(.orange.opacity(0.12))
            }
        }
    }
    private var overview: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                Label("Secrets on this Mac", systemImage: "key.horizontal").font(.largeTitle.bold())
                Text("Browse encrypted environment files, compare environments, and save encrypted edits. Esec opens values locally in memory.").foregroundStyle(.secondary)
                HStack {
                    Button("Add Project Folder…") { store.chooseFolder() }.buttonStyle(.borderedProminent)
                    Button("Open Secrets File…") { store.chooseSecretFile() }
                }
                GroupBox("Local identities") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Run esec setup to configure your developer identity and YubiKey recipients.")
                        Text("Production access uses the recipients configured for that environment. Connect your YubiKey and approve its PIN/touch prompt when asked.").foregroundStyle(.secondary)
                        Text("Esec \(store.version)").font(.caption).textSelection(.enabled)
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
                GroupBox("Remembered folders") {
                    VStack(alignment: .leading) {
                        if store.folders.isEmpty { Text("Add a project or a parent folder to begin.").foregroundStyle(.secondary) }
                        ForEach(store.folders, id: \.self) { folder in
                            HStack {
                                Text((folder as NSString).abbreviatingWithTildeInPath).textSelection(.enabled)
                                Spacer()
                                Button("Forget") { store.forget(folder) }.buttonStyle(.borderless).help("Remove from this app's list; files and keys stay on disk")
                            }.padding(.vertical, 4)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
            }.padding(30).frame(maxWidth: 900, alignment: .leading)
        }
    }
}
struct ProjectDetail: View {
    @Environment(Store.self) private var store
    let project: Project
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                VStack(alignment: .leading) { Text(project.project).font(.title.bold()); Text(project.path).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
                Spacer()
                Button("Compare Environments", systemImage: "tablecells") { store.compare(project) }.disabled((project.files ?? []).isEmpty)
            }
            List(project.files ?? []) { file in
                Button { store.openSecretFile(file.path) } label: {
                    HStack {
                        Image(systemName: "doc.text.lock")
                        VStack(alignment: .leading, spacing: 4) {
                            Text(URL(fileURLWithPath: file.path).lastPathComponent).font(.headline)
                            Text("\(file.env) · \(file.keys?.count ?? 0) keys").font(.caption).foregroundStyle(.secondary)
                            Text(file.path).font(.caption2).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                        }
                        Spacer()
                        if !(file.plain ?? []).isEmpty { Label("Unencrypted values", systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
                        Image(systemName: "arrow.up.forward.app")
                    }.padding(.vertical, 6).contentShape(Rectangle())
                }.buttonStyle(.plain)
            }
            Text("Open a file to decrypt it in memory. Saved edits are encrypted by Esec before replacing the file.").font(.caption).foregroundStyle(.secondary)
        }.padding(24)
    }
}
