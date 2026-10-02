import XCTest

/// Drives the demo wallet end to end against mobile/cmd/testservices,
/// which run-ui-tests.sh starts and whose certificate it installs into
/// the Simulator.
final class DemoWalletUITests: XCTestCase {
    static let control = URL(string: "https://127.0.0.1:8600")!

    /// Asks the test services' control endpoint.
    nonisolated static func fetch(_ path: String, query: [URLQueryItem] = [], method: String = "GET") async throws -> [String: Any] {
        var request = URLRequest(url: control.appending(path: path).appending(queryItems: query))
        request.httpMethod = method
        let (data, _) = try await URLSession.shared.data(for: request)
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    @MainActor
    func launch(offer: String) async throws -> XCUIApplication {
        let config = try await Self.fetch("config")
        let app = XCUIApplication()
        app.launchEnvironment["OID4VC_DEMO_CONFIG"] = String(decoding: try JSONSerialization.data(withJSONObject: config), as: UTF8.self)
        app.launchEnvironment["OID4VC_DEMO_OFFER"] = offer
        app.launch()
        return app
    }

    /// The authorization code grant: the issuer's page opens in an
    /// ephemeral web session, approves, and redirects back to the app.
    @MainActor
    func testReceiveWithAuthorizationCode() async throws {
        // fapigo/server refuses the app's private-use scheme redirect URI
        // at the Pushed Authorization Request (it accepts https only),
        // though FAPI 2.0 doesn't forbid one; asked of FAPIgo — see
        // MOBILE.md's Phase 4 findings.
        throw XCTSkip("waiting on FAPIgo accepting native-app redirect URIs (RFC 8252 §7.1)")
        let offer = try await Self.fetch("offer", method: "POST")["offer"] as! String
        let app = try await launch(offer: offer)
        let receive = app.buttons["receive"]
        XCTAssertTrue(receive.waitForExistence(timeout: 20))
        receive.tap()
        let status = app.staticTexts["status"]
        XCTAssertTrue(status.waitForExistence(timeout: 60))
        XCTAssertTrue(status.label.hasPrefix("Received 2"), status.label)
        XCTAssertGreaterThanOrEqual(app.descendants(matching: .any).matching(identifier: "credential").count, 2)
    }

    /// The pre-authorized code grant, with the PIN typed in the app.
    @MainActor
    func testReceiveWithPIN() async throws {
        let offer = try await Self.fetch("offer", query: [URLQueryItem(name: "pin", value: "493536")], method: "POST")["offer"] as! String
        let app = try await launch(offer: offer)
        let pin = app.textFields["pin"]
        XCTAssertTrue(pin.waitForExistence(timeout: 20))
        pin.tap()
        pin.typeText("493536")
        app.buttons["receive"].tap()
        let status = app.staticTexts["status"]
        XCTAssertTrue(status.waitForExistence(timeout: 60))
        XCTAssertTrue(status.label.hasPrefix("Received 1"), status.label)
    }
}
