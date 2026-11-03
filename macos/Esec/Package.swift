// swift-tools-version:6.0
import PackageDescription
let package = Package(name: "Esec", platforms: [.macOS(.v14)], products: [.executable(name: "Esec", targets: ["Esec"])], targets: [
    .target(name: "EsecCore"),
    .target(name: "EsecUI", dependencies: ["EsecCore"]),
    .executableTarget(name: "Esec", dependencies: ["EsecUI"]),
    .testTarget(name: "EsecTests", dependencies: ["EsecCore", "EsecUI"])
])
