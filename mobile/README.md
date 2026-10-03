# OID4VCgo mobile

The gomobile boundary of OID4VCgo's mobile wallet SDK — see
[MOBILE.md](../MOBILE.md) for the design and its phases. This is a
separate Go module (it needs `golang.org/x/mobile`).

- `mobile` (this directory): the Go package `gomobile bind` compiles.
- `ios/OID4VCMobile`: the Swift package wrapping the XCFramework, with
  its tests.

The API is described in [ABI.md](ABI.md).

Build the XCFramework (Xcode and Go needed; gomobile and gobind are the
versions `go.mod` pins). The Swift tests need the test build, which adds
an in-process test issuer and Verifier (`TestEnv`) a shipped framework
must not have:

```sh
./build-xcframework.sh -tags mobiletest   # → build/test/Mobile.xcframework
./build-xcframework.sh                    # → build/release/Mobile.xcframework, the one an app ships
cd ios/OID4VCMobile
OID4VC_TEST_FRAMEWORK=1 swift test        # macOS slice, against the test build
OID4VC_TEST_FRAMEWORK=1 xcodebuild test -scheme OID4VCMobile -destination 'platform=iOS Simulator,name=iPhone 16'
```

The package links the release build unless `OID4VC_TEST_FRAMEWORK=1`
is set, and `OID4VC.isTestBuild` says which one an app has.

The Go package's own tests run anywhere: `go test -tags mobiletest ./...`
for the end-to-end session tests too.
