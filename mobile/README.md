# OID4VCgo mobile

The gomobile boundary of OID4VCgo's mobile wallet SDK — see
[MOBILE.md](../MOBILE.md) for the design and its phases. This is a
separate Go module (it needs `golang.org/x/mobile`).

- `mobile` (this directory): the Go package `gomobile bind` compiles.
- `ios/OID4VCMobile`: the Swift package wrapping the XCFramework, with
  its tests.

Build the XCFramework (Xcode and Go needed; gomobile and gobind are the
versions `go.mod` pins), then run the Swift tests on macOS or the iOS
Simulator:

```sh
./build-xcframework.sh                # → build/Mobile.xcframework
cd ios/OID4VCMobile
swift test                            # macOS slice
xcodebuild test -scheme OID4VCMobile -destination 'platform=iOS Simulator,name=iPhone 16'
```

The Go package's own tests run anywhere: `go test ./...`.
