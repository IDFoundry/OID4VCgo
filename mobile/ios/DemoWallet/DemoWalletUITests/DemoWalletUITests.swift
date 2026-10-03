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
    func launch(offer: String? = nil, request: String? = nil, reset: Bool = true) async throws -> XCUIApplication {
        let config = try await Self.fetch("config")
        let app = XCUIApplication()
        app.launchEnvironment["OID4VC_DEMO_CONFIG"] = String(decoding: try JSONSerialization.data(withJSONObject: config), as: UTF8.self)
        app.launchEnvironment["OID4VC_DEMO_OFFER"] = offer
        app.launchEnvironment["OID4VC_DEMO_REQUEST"] = request
        app.launchEnvironment["OID4VC_DEMO_RESET"] = reset ? "1" : "0"
        app.launch()
        return app
    }

    /// The authorization code grant: the issuer's page opens in an
    /// ephemeral web session, approves, and redirects back to the app.
    @MainActor
    func testReceiveWithAuthorizationCode() async throws {
        let offer = try await Self.fetch("offer", method: "POST")["offer"] as! String
        let app = try await launch(offer: offer)
        let receive = app.buttons["receive"]
        XCTAssertTrue(receive.waitForExistence(timeout: 20))
        receive.tap()
        let status = app.staticTexts["status"]
        XCTAssertTrue(status.waitForExistence(timeout: 60))
        XCTAssertTrue(status.label.hasPrefix("Received 2"), status.label)
        let credentials = app.descendants(matching: .any).matching(identifier: "credential")
        XCTAssertTrue(credentials.element(boundBy: 1).waitForExistence(timeout: 10), "the two credentials aren't listed")
        XCTAssertEqual(credentials.count, 2)

        // A credential's claims.
        credentials.element(boundBy: 0).tap()
        let family = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS 'Doe'")).firstMatch
        XCTAssertTrue(family.waitForExistence(timeout: 10), "family_name isn't shown")
        XCTAssertTrue(app.images["portrait"].waitForExistence(timeout: 10), "the portrait isn't shown as an image")
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

    /// A wrong PIN keeps the offer open, saying so; the right one then
    /// receives the credential.
    @MainActor
    func testWrongPINThenRetry() async throws {
        let offer = try await Self.fetch("offer", query: [URLQueryItem(name: "pin", value: "493536")], method: "POST")["offer"] as! String
        let app = try await launch(offer: offer)
        let pin = app.textFields["pin"]
        XCTAssertTrue(pin.waitForExistence(timeout: 20))
        pin.tap()
        pin.typeText("000000")
        app.buttons["receive"].tap()
        let error = app.staticTexts["offer-error"]
        XCTAssertTrue(error.waitForExistence(timeout: 30), "a wrong PIN isn't reported on the offer")
        XCTAssertTrue(error.label.contains("PIN"), error.label)
        pin.tap()
        pin.typeText("493536")
        app.buttons["receive"].tap()
        let status = app.staticTexts["status"]
        XCTAssertTrue(status.waitForExistence(timeout: 60))
        XCTAssertTrue(status.label.hasPrefix("Received 1"), status.label)
    }

    /// Receives an SD-JWT VC, then presents it: the Verifier asks for
    /// family_name from either format, the holder shares the one
    /// credential held, and the Verifier gets the claim.
    @MainActor
    func testPresent() async throws {
        let offer = try await Self.fetch("offer", query: [URLQueryItem(name: "pin", value: "493536")], method: "POST")["offer"] as! String
        let app = try await launch(offer: offer)
        let pin = app.textFields["pin"]
        XCTAssertTrue(pin.waitForExistence(timeout: 20))
        pin.tap()
        pin.typeText("493536")
        app.buttons["receive"].tap()
        XCTAssertTrue(app.staticTexts["status"].waitForExistence(timeout: 60))

        // Open the request in the app, relaunched with it (opening a
        // custom-scheme link from a test asks for confirmation).
        let request = try await Self.fetch("request", method: "POST")
        app.terminate()
        let presenting = try await launch(request: request["link"] as? String, reset: false)
        let share = presenting.buttons["share"]
        XCTAssertTrue(share.waitForExistence(timeout: 20))
        XCTAssertTrue(presenting.staticTexts["family_name"].waitForExistence(timeout: 10), "the disclosure isn't shown")
        share.tap()
        let status = presenting.staticTexts["status"]
        XCTAssertTrue(status.waitForExistence(timeout: 30))
        let shared = NSPredicate(format: "label BEGINSWITH 'Shared with'")
        await fulfillment(of: [XCTNSPredicateExpectation(predicate: shared, object: status)], timeout: 30)

        let result = try await Self.fetch("request/\(request["id"] as! String)")
        XCTAssertEqual(result["status"] as? String, "done")
        XCTAssertEqual((result["claims"] as? [String: Any])?["family_name"] as? String, "Doe")
    }

    /// Declines a request the wallet can't answer; the Verifier records
    /// it.
    @MainActor
    func testDecline() async throws {
        let request = try await Self.fetch("request", query: [URLQueryItem(name: "format", value: "mso_mdoc")], method: "POST")
        let app = try await launch(request: request["link"] as? String)
        let decline = app.buttons["decline"]
        XCTAssertTrue(decline.waitForExistence(timeout: 20))
        XCTAssertFalse(app.buttons["share"].isEnabled)
        decline.tap()
        let status = app.staticTexts["status"]
        XCTAssertTrue(status.waitForExistence(timeout: 30))
        XCTAssertTrue(status.label.hasPrefix("Declined"), status.label)
        let result = try await Self.fetch("request/\(request["id"] as! String)")
        XCTAssertTrue((result["last_error"] as? String ?? "").contains("access_denied"), "\(result)")
    }

    /// The scanner: on the Simulator, which has no camera, it offers a QR
    /// code image from Photos instead.
    @MainActor
    func testScanSheet() async throws {
        let app = try await launch()
        app.buttons["scan"].tap()
        XCTAssertTrue(app.buttons["choose-image"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["No camera scanning here"].exists)
        app.buttons["Cancel"].tap()
        XCTAssertTrue(app.buttons["scan"].waitForExistence(timeout: 10))
    }

    /// Receives a credential the issuer defers, as passport-vdc's review
    /// mode does: it waits, polled at the issuer's interval, until the
    /// issuer decides.
    @MainActor
    func receiveDeferred() async throws -> XCUIApplication {
        _ = try await Self.fetch("defer", query: [URLQueryItem(name: "on", value: "1")], method: "POST")
        addTeardownBlock {
            _ = try? await Self.fetch("defer", query: [URLQueryItem(name: "on", value: "0")], method: "POST")
        }
        let offer = try await Self.fetch("offer", query: [URLQueryItem(name: "pin", value: "493536")], method: "POST")["offer"] as! String
        let app = try await launch(offer: offer)
        let pin = app.textFields["pin"]
        XCTAssertTrue(pin.waitForExistence(timeout: 20))
        pin.tap()
        pin.typeText("493536")
        app.buttons["receive"].tap()
        let status = app.staticTexts["status"]
        XCTAssertTrue(status.waitForExistence(timeout: 60))
        XCTAssertTrue(status.label.hasSuffix("1 deferred"), status.label)
        XCTAssertTrue(app.buttons["check-again"].waitForExistence(timeout: 10))
        return app
    }

    @MainActor
    func testDeferredApproved() async throws {
        let app = try await receiveDeferred()
        // Still pending: polling finds nothing yet.
        XCTAssertEqual(app.descendants(matching: .any).matching(identifier: "credential").count, 0)
        _ = try await Self.fetch("decide", query: [URLQueryItem(name: "approve", value: "1")], method: "POST")
        // The test issuer's poll interval is a second: automatic polling
        // settles it, and a Check again tap would race it.
        let credential = app.descendants(matching: .any).matching(identifier: "credential").firstMatch
        XCTAssertTrue(credential.waitForExistence(timeout: 30), "the approved credential isn't listed")
        XCTAssertFalse(app.buttons["check-again"].exists, "it's still listed as pending")
    }

    /// A pending credential survives the app quitting: relaunched, the
    /// app resumes polling it, and receives it once approved.
    @MainActor
    func testDeferredSurvivesARelaunch() async throws {
        let app = try await receiveDeferred()
        app.terminate()
        let relaunched = try await launch(reset: false)
        XCTAssertTrue(relaunched.buttons["check-again"].waitForExistence(timeout: 20), "the pending credential wasn't resumed")
        XCTAssertEqual(relaunched.descendants(matching: .any).matching(identifier: "credential").count, 0)
        _ = try await Self.fetch("decide", query: [URLQueryItem(name: "approve", value: "1")], method: "POST")
        let credential = relaunched.descendants(matching: .any).matching(identifier: "credential").firstMatch
        XCTAssertTrue(credential.waitForExistence(timeout: 30), "the approved credential isn't listed")
    }

    @MainActor
    func testDeferredDenied() async throws {
        let app = try await receiveDeferred()
        _ = try await Self.fetch("decide", query: [URLQueryItem(name: "approve", value: "0")], method: "POST")
        // The test issuer's poll interval is a second: automatic polling
        // settles it, and a Check again tap would race it.
        let dismiss = app.buttons["dismiss"]
        XCTAssertTrue(dismiss.waitForExistence(timeout: 30), "the denial isn't shown")
        let state = app.staticTexts["pending-state"]
        XCTAssertTrue(state.label.contains("Denied"), state.label)
        dismiss.tap()
        XCTAssertFalse(app.descendants(matching: .any).matching(identifier: "pending").firstMatch.waitForExistence(timeout: 3))
        XCTAssertEqual(app.descendants(matching: .any).matching(identifier: "credential").count, 0)
    }
}
