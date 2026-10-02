// swift-tools-version:6.0
import PackageDescription

// The Swift face of OID4VCgo's gomobile boundary (the Go "mobile"
// package): build ../../build/Mobile.xcframework first with
// ../../build-xcframework.sh.
let package = Package(
    name: "OID4VCMobile",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "OID4VCMobile", targets: ["OID4VCMobile"])],
    targets: [
        .binaryTarget(name: "Mobile", path: "../../build/Mobile.xcframework"),
        .target(name: "OID4VCMobile", dependencies: ["Mobile"]),
        .testTarget(name: "OID4VCMobileTests", dependencies: ["OID4VCMobile"]),
    ]
)
