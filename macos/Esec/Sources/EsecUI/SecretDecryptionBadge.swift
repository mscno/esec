import EsecCore
import SwiftUI

struct SecretDecryptionBadge: View {
    let info: SecretDecryption?

    private var title: String { info?.title ?? "Route unavailable" }
    private var explanation: String {
        info?.explanation ?? "This CLI did not report the route used for the last successful decryption. Update the app and its CLI to see this information."
    }

    var body: some View {
        Label(title, systemImage: info?.symbol ?? "info.circle")
            .font(.caption)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 8).padding(.vertical, 4)
            .background(.quaternary, in: Capsule())
            .fixedSize()
            .help(explanation)
            .accessibilityLabel("Decryption route: " + title)
            .accessibilityHint(explanation)
    }
}
