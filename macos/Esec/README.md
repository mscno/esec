# Esec for macOS

A local credential browser for Esec 0.19+. Build with `./bundle.sh` from this
folder (Xcode with Swift 6 and Go required), or download the matching app from
[Esec releases](https://github.com/mscno/esec/releases).

`Esec.app` contains the native `EsecApp` executable and the matching `esec` CLI.
Every crypto operation uses a short-lived CLI process. There is no helper,
daemon, broker, or network service. Install age-plugin-yubikey separately if
using hardware identities; the app searches the usual Homebrew locations.

The app scans chosen local folders for encrypted files, remembers their paths,
and imports legacy checkout paths once. It never discovers secret values in
background scans. Values are decrypted in memory on request and edits are
revision checked, encrypted by the CLI, and journaled as ciphertext.
Hardware prompt replies and edit values use stdin, never argv or temporary files.

Run tests with `swift test`. Synthetic fixtures cover document locking, stale
saves, visibility, environment ordering, and interactive protocol cancellation.
Physical YubiKey approval also needs a manual hardware test.

Published builds are ad-hoc signed and carry checksums/build provenance, but are
not Developer ID signed or notarized.
