// swift-tools-version:5.5
import PackageDescription

let package = Package(
  name: "SPKIHashVerifier",
  platforms: [.iOS(.v11), .watchOS(.v3), .tvOS(.v10), .macOS(.v10_13)],
  products: [.library(name: "SPKIHashVerifier", targets: ["SPKIHashVerifier"])],
  dependencies: [],
  targets: [
    .target(name: "SPKIHashVerifier", dependencies: []),
    .testTarget(name: "SPKIHashVerifierTests", dependencies: ["SPKIHashVerifier"]),
  ]
)
