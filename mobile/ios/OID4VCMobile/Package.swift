// swift-tools-version:6.0
import PackageDescription

// The Swift face of OID4VCgo's gomobile boundary (the Go "mobile"
// package). Build the framework first with ../../build-xcframework.sh:
// the release build by default; with OID4VC_TEST_FRAMEWORK=1 set, the
// package links the test build instead (`-tags mobiletest`), which the
// tests need — they drive its in-process test issuer and Verifier.
let testBuild = Context.environment["OID4VC_TEST_FRAMEWORK"] == "1"
let framework = testBuild ? "../../build/test/Mobile.xcframework" : "../../build/release/Mobile.xcframework"

let package = Package(
    name: "OID4VCMobile",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "OID4VCMobile", targets: ["OID4VCMobile"])],
    targets: [
        .binaryTarget(name: "Mobile", path: framework),
        .target(name: "OID4VCMobile", dependencies: ["Mobile"]),
        .testTarget(name: "OID4VCMobileTests", dependencies: ["OID4VCMobile", "Mobile"]),
    ]
)
