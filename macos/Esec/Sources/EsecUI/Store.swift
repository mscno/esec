import AppKit
import EsecCore
import Observation
import ServiceManagement

@MainActor @Observable
final class Store {
    static let shared = Store()
    private static let preferences = ProcessInfo.processInfo.environment["ESEC_APP_PREFERENCES_SUITE"].flatMap(UserDefaults.init(suiteName:)) ?? .standard
    var cli = CLI.locate()
    var projects: [Project] = []
    var folders: [String] = Store.preferences.stringArray(forKey: "Esec.checkouts.v1") ?? []
    var errors: [String: String] = [:]
    var search = ""
    var refreshing = false
    var version = ""
    var started = false
    @ObservationIgnored private var windows: [String: SecretFileWindow] = [:]
    @ObservationIgnored private var comparisons: [String: SecretComparisonWindow] = [:]

    var filteredProjects: [Project] {
        projects.filter { search.isEmpty || $0.project.localizedCaseInsensitiveContains(search) || $0.path.localizedCaseInsensitiveContains(search) }
    }
    func start() {
        guard !started else { return }; started = true
        Task {
            guard let cli else { errors["CLI"] = "Reinstall Esec: its bundled CLI was not found."; return }
            do {
                let capabilities = String(decoding: try await cli.run(["capabilities"]), as: UTF8.self)
                guard capabilities.contains("local-documents-v1") else { errors["CLI"] = "This CLI is too old for the local browser. Install Esec 0.19 or later."; return }
                version = String(decoding: try await cli.run(["--version"]), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                if !Self.preferences.bool(forKey: "Esec.importedCheckouts.v1") {
                    let data = try await cli.run(["files", "--registered"])
                    let known = try JSON.decoder.decode([String].self, from: data)
                    folders = Array(Set(folders + known)).sorted(); saveFolders()
                    Self.preferences.set(true, forKey: "Esec.importedCheckouts.v1")
                }
                await refresh()
            } catch { errors["CLI"] = error.localizedDescription }
        }
    }
    func refresh() async {
        guard let cli, !refreshing else { return }; refreshing = true
        defer { refreshing = false }
        var byPath: [String: SecretsFile] = [:]
        errors = [:]
        for folder in folders {
            do { for file in try await cli.files(in: folder) { byPath[file.path] = file } }
            catch { errors[folder] = error.localizedDescription }
        }
        let grouped = Dictionary(grouping: Array(byPath.values)) { $0.root ?? URL(fileURLWithPath: $0.path).deletingLastPathComponent().path }
        projects = grouped.map { path, files in
            Project(project: files.first?.project ?? URL(fileURLWithPath: path).lastPathComponent, path: path, files: files.sorted { $0.path < $1.path })
        }.sorted { $0.project == $1.project ? $0.path < $1.path : $0.project < $1.project }
    }
    func chooseFolder() {
        let panel = NSOpenPanel(); panel.canChooseFiles = false; panel.canChooseDirectories = true
        panel.message = "Choose a project, or a parent folder to find encrypted environment files."
        panel.prompt = "Add Folder"
        if panel.runModal() == .OK, let url = panel.url {
            folders = Array(Set(folders + [url.resolvingSymlinksInPath().path])).sorted(); saveFolders()
            Task { await refresh() }
        }
    }
    func forget(_ folder: String) { folders.removeAll { $0 == folder }; saveFolders(); Task { await refresh() } }
    private func saveFolders() { Self.preferences.set(folders, forKey: "Esec.checkouts.v1") }
    func chooseSecretFile() {
        let panel = NSOpenPanel(); panel.showsHiddenFiles = true; panel.canChooseDirectories = false
        panel.message = "Open an encrypted file. Esec decrypts its values in memory."
        if panel.runModal() == .OK, let url = panel.url { openSecretFile(url.path) }
    }
    func openSecretFile(_ path: String) {
        guard let cli else { return }
        let path = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        let controller = windows[path] ?? SecretFileWindow(path: path, cli: cli)
        controller.onClose = { [weak self] in self?.windows[path] = nil }; windows[path] = controller
        controller.showWindow(nil); controller.window?.makeKeyAndOrderFront(nil); NSApp.activate()
    }
    func compare(_ project: Project) {
        guard let cli else { return }
        let controller = comparisons[project.id] ?? SecretComparisonWindow(project: project, cli: cli) { [weak self] in self?.openSecretFile($0) }
        controller.onClose = { [weak self] in self?.comparisons[project.id] = nil }; comparisons[project.id] = controller
        controller.showWindow(nil); controller.window?.makeKeyAndOrderFront(nil); NSApp.activate()
    }
    func lockAll() { windows.values.forEach { $0.model.lock() }; comparisons.values.forEach { $0.model.lock() }; CLI.cancelAll() }
    var opensAtLogin: Bool {
        get { SMAppService.mainApp.status == .enabled }
        set { do { if newValue { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() } } catch { errors["Login"] = error.localizedDescription } }
    }
}
