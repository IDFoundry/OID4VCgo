import XCTest
@testable import DemoWallet

final class QRCodeTests: XCTestCase {
    func testReadsAWalletLink() throws {
        let link = "openid4vp://?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Fverifier.example%2Fr%2F1"
        let image = try XCTUnwrap(QRCode.image(of: link))
        XCTAssertEqual(try QRCode.payloads(in: image), [link])
        XCTAssertEqual(try QRCode.walletLink(in: image)?.absoluteString, link)
    }

    func testIgnoresOtherLinks() throws {
        let image = try XCTUnwrap(QRCode.image(of: "https://example.com/not-a-wallet-link"))
        XCTAssertNil(try QRCode.walletLink(in: image))
    }
}
