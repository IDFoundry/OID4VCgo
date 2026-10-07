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
    func launch(offer: String? = nil, request: String? = nil, reset: Bool = true, trustVerifier: Bool = true) async throws -> XCUIApplication {
        var config = try await Self.fetch("config")
        if !trustVerifier, var wallet = config["wallet"] as? [String: Any] {
            // Another CA: the issuer's.
            wallet["verifier_roots"] = wallet["issuer_roots"]
            config["wallet"] = wallet
        }
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
        // Below the fold on a taller layout (iOS 27): a List makes a row
        // only once it scrolls into view.
        XCTAssertTrue(reveal(app.images["portrait"], in: app, wait: 5), "the portrait isn't shown as an image")
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

    /// A received credential shows its status, checked against the
    /// issuer's status list: valid, then revoked once the issuer revokes
    /// it.
    @MainActor
    func testCheckStatusAndRevocation() async throws {
        let offer = try await Self.fetch("offer", query: [URLQueryItem(name: "pin", value: "493536")], method: "POST")["offer"] as! String
        let app = try await launch(offer: offer)
        let pin = app.textFields["pin"]
        XCTAssertTrue(pin.waitForExistence(timeout: 20))
        pin.tap()
        pin.typeText("493536")
        app.buttons["receive"].tap()
        let credential = app.descendants(matching: .any).matching(identifier: "credential").firstMatch
        XCTAssertTrue(credential.waitForExistence(timeout: 60))
        XCTAssertTrue(credential.label.contains("Test PID"), credential.label)
        credential.tap()
        let check = app.buttons["check-status"]
        XCTAssertTrue(check.waitForExistence(timeout: 10))
        check.tap()
        let status = app.descendants(matching: .any).matching(identifier: "credential-status").firstMatch
        XCTAssertTrue(status.waitForExistence(timeout: 10))
        XCTAssertTrue(waitFor(status, containing: "Valid"), status.label)
        // The check says it happened.
        XCTAssertTrue(app.descendants(matching: .any).matching(identifier: "check-done").firstMatch.waitForExistence(timeout: 10),
                      "no feedback that the check happened")
        _ = try await Self.fetch("revoke", method: "POST")
        check.tap()
        XCTAssertTrue(waitFor(status, containing: "Revoked"), status.label)
    }

    /// Waits up to 10 seconds for element's label to contain text.
    @MainActor
    func waitFor(_ element: XCUIElement, containing text: String) -> Bool {
        let expectation = XCTNSPredicateExpectation(predicate: NSPredicate(format: "label CONTAINS %@", text), object: element)
        return XCTWaiter().wait(for: [expectation], timeout: 10) == .completed
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

        // The home screen groups the credential under its holder.
        let holderHeader = app.descendants(matching: .any).matching(identifier: "holder").firstMatch
        XCTAssertTrue(holderHeader.waitForExistence(timeout: 10), "the credentials aren't grouped by holder")
        XCTAssertTrue(holderHeader.label.contains("Doe"), holderHeader.label)

        // Open the request in the app, relaunched with it (opening a
        // custom-scheme link from a test asks for confirmation).
        let request = try await Self.fetch("request", method: "POST")
        app.terminate()
        let presenting = try await launch(request: request["link"] as? String, reset: false)
        let share = presenting.buttons["share"]
        XCTAssertTrue(share.waitForExistence(timeout: 20))
        // Whose credential it is, and the value sharing discloses.
        let holder = presenting.staticTexts.matching(identifier: "candidate-holder").firstMatch
        XCTAssertTrue(holder.waitForExistence(timeout: 10), "the candidate doesn't say whose it is")
        XCTAssertTrue(holder.label.contains("Doe"), holder.label)
        let disclosed = presenting.descendants(matching: .any).matching(identifier: "disclosed")
            .matching(NSPredicate(format: "label CONTAINS 'family_name'")).firstMatch
        XCTAssertTrue(disclosed.waitForExistence(timeout: 10), "the disclosure isn't shown")
        XCTAssertTrue(waitFor(disclosed, containing: "Doe"), disclosed.label)
        share.tap()
        let status = presenting.staticTexts["status"]
        XCTAssertTrue(status.waitForExistence(timeout: 30))
        let shared = NSPredicate(format: "label BEGINSWITH 'Shared with'")
        await fulfillment(of: [XCTNSPredicateExpectation(predicate: shared, object: status)], timeout: 30)

        let result = try await Self.fetch("request/\(request["id"] as! String)")
        XCTAssertEqual(result["status"] as? String, "done")
        XCTAssertEqual((result["claims"] as? [String: Any])?["family_name"] as? String, "Doe")

        // The issuer issued three copies; presenting used one.
        let credential = presenting.descendants(matching: .any).matching(identifier: "credential").firstMatch
        XCTAssertTrue(credential.waitForExistence(timeout: 10))
        XCTAssertTrue(waitFor(credential, containing: "2 of 3 copies unused"), credential.label)
    }

    /// Receives a credential with the PIN, in an app launched fresh or,
    /// with reset false, keeping what it holds.
    @MainActor
    func receiveWithPIN(reset: Bool) async throws -> XCUIApplication {
        let offer = try await Self.fetch("offer", query: [URLQueryItem(name: "pin", value: "493536")], method: "POST")["offer"] as! String
        let app = try await launch(offer: offer, reset: reset)
        let pin = app.textFields["pin"]
        XCTAssertTrue(pin.waitForExistence(timeout: 20))
        pin.tap()
        pin.typeText("493536")
        app.buttons["receive"].tap()
        let status = app.staticTexts["status"]
        XCTAssertTrue(status.waitForExistence(timeout: 60))
        XCTAssertTrue(status.label.hasPrefix("Received 1"), status.label)
        return app
    }

    /// A request that takes several credentials (DCQL multiple): both
    /// held are offered and chosen, unchoosing one leaves the other
    /// chosen, and sharing both reaches the Verifier as two.
    @MainActor
    func testPresentSeveral() async throws {
        try await receiveWithPIN(reset: true).terminate()
        try await receiveWithPIN(reset: false).terminate()

        let request = try await Self.fetch("request", query: [
            URLQueryItem(name: "format", value: "dc+sd-jwt"), URLQueryItem(name: "multiple", value: "1"),
        ], method: "POST")
        let app = try await launch(request: request["link"] as? String, reset: false)
        let share = app.buttons["share"]
        let candidates = app.buttons.matching(identifier: "candidate")
        XCTAssertTrue(candidates.element(boundBy: 1).waitForExistence(timeout: 10), "both credentials aren't offered")
        XCTAssertEqual(candidates.count, 2)
        let first = candidates.element(boundBy: 0)
        let second = candidates.element(boundBy: 1)
        XCTAssertTrue(first.isSelected && second.isSelected, "the request takes several, so both start chosen")

        first.tap()
        XCTAssertTrue(waitForSelected(first, false) && second.isSelected, "unchoosing one unchose the other")
        first.tap()
        XCTAssertTrue(waitForSelected(first, true) && second.isSelected, "choosing one unchose the other")
        XCTAssertTrue(reveal(share, in: app))
        let enabled = NSPredicate(format: "isEnabled == true")
        await fulfillment(of: [XCTNSPredicateExpectation(predicate: enabled, object: share)], timeout: 10)
        share.tap()
        let status = app.staticTexts["status"]
        XCTAssertTrue(status.waitForExistence(timeout: 30))
        await fulfillment(of: [XCTNSPredicateExpectation(predicate: NSPredicate(format: "label BEGINSWITH 'Shared with'"), object: status)], timeout: 30)

        let result = try await Self.fetch("request/\(request["id"] as! String)")
        XCTAssertEqual(result["status"] as? String, "done")
        XCTAssertEqual(result["credentials"] as? Int, 2, "\(result)")
    }

    /// Waits up to 10 seconds for element to be chosen, or not.
    @MainActor
    func waitForSelected(_ element: XCUIElement, _ selected: Bool) -> Bool {
        let expectation = XCTNSPredicateExpectation(predicate: NSPredicate(format: "isSelected == %@", NSNumber(value: selected)), object: element)
        return XCTWaiter().wait(for: [expectation], timeout: 10) == .completed
    }

    /// Credentials received by authorization code keep a refresh token:
    /// after a presentation uses a copy, Refresh copies replaces them
    /// with a fresh batch, every copy unused again.
    @MainActor
    func testRefreshCopies() async throws {
        let offer = try await Self.fetch("offer", method: "POST")["offer"] as! String
        let receiving = try await launch(offer: offer)
        let receive = receiving.buttons["receive"]
        XCTAssertTrue(receive.waitForExistence(timeout: 20))
        receive.tap()
        let received = receiving.staticTexts["status"]
        XCTAssertTrue(received.waitForExistence(timeout: 60))
        XCTAssertTrue(received.label.hasPrefix("Received 2"), received.label)
        receiving.terminate()

        let request = try await Self.fetch("request", query: [URLQueryItem(name: "format", value: "dc+sd-jwt")], method: "POST")
        let app = try await launch(request: request["link"] as? String, reset: false)
        let share = app.buttons["share"]
        XCTAssertTrue(share.waitForExistence(timeout: 20))
        await fulfillment(of: [XCTNSPredicateExpectation(predicate: NSPredicate(format: "isEnabled == true"), object: share)], timeout: 10)
        share.tap()
        let status = app.staticTexts["status"]
        XCTAssertTrue(status.waitForExistence(timeout: 30))
        await fulfillment(of: [XCTNSPredicateExpectation(predicate: NSPredicate(format: "label BEGINSWITH 'Shared with'"), object: status)], timeout: 30)

        let used = app.descendants(matching: .any).matching(identifier: "credential")
            .matching(NSPredicate(format: "label CONTAINS '2 of 3 copies unused'")).firstMatch
        XCTAssertTrue(used.waitForExistence(timeout: 10), "the presented credential doesn't show a copy used")
        used.tap()
        let copies = app.staticTexts["credential-copies"]
        XCTAssertTrue(copies.waitForExistence(timeout: 10))
        XCTAssertTrue(copies.label.contains("2 of 3"), copies.label)
        app.buttons["refresh-copies"].tap()
        XCTAssertTrue(waitFor(copies, containing: "3 of 3 copies unused"), copies.label)
        let done = app.descendants(matching: .any).matching(identifier: "refresh-done").firstMatch
        XCTAssertTrue(done.waitForExistence(timeout: 10), "no feedback that the refresh happened")
        XCTAssertTrue(done.label.contains("3 fresh copies"), done.label)
    }

    /// Once every copy of a refreshable credential has been presented, the
    /// app refreshes it by itself: fresh copies, none presented.
    @MainActor
    func testAutoRefresh() async throws {
        var current = try await receiveWithPIN(reset: true)
        for _ in 0..<3 {
            let request = try await Self.fetch("request", query: [URLQueryItem(name: "format", value: "dc+sd-jwt")], method: "POST")
            current = try await presentOnce(current, link: request["link"] as! String)
            current.buttons["share"].tap()
            let status = current.staticTexts["status"]
            XCTAssertTrue(status.waitForExistence(timeout: 30))
            await fulfillment(of: [XCTNSPredicateExpectation(predicate: NSPredicate(format: "label BEGINSWITH 'Shared with'"), object: status)], timeout: 30)
        }
        // The one credential received: after its third presentation it
        // would show no copy unused.
        let credential = current.descendants(matching: .any).matching(identifier: "credential").firstMatch
        XCTAssertTrue(credential.waitForExistence(timeout: 10))
        XCTAssertTrue(waitFor(credential, containing: "3 of 3 copies unused"), credential.label)
    }

    /// Waits for element, scrolling to it: a long consent screen builds
    /// its rows only once they're on screen, so one at the top goes once
    /// the screen is scrolled down to Share.
    @MainActor
    func reveal(_ element: XCUIElement, in app: XCUIApplication, wait: TimeInterval = 20) -> Bool {
        if element.waitForExistence(timeout: wait) { return true }
        // Down first, then back up: a List makes only the rows in view,
        // and a taller layout (iOS 27) leaves more of them out of it.
        for _ in 0..<4 {
            app.swipeUp()
            if element.waitForExistence(timeout: 2) { return true }
        }
        for _ in 0..<8 {
            app.swipeDown()
            if element.waitForExistence(timeout: 2) { return true }
        }
        return false
    }

    /// Presents to one verifier, through the consent screen, and waits
    /// for the result.
    @MainActor
    func presentOnce(_ app: XCUIApplication, link: String) async throws -> XCUIApplication {
        app.terminate()
        let presenting = try await launch(request: link, reset: false)
        let share = presenting.buttons["share"]
        XCTAssertTrue(reveal(share, in: presenting))
        await fulfillment(of: [XCTNSPredicateExpectation(predicate: NSPredicate(format: "isEnabled == true"), object: share)], timeout: 10)
        return presenting
    }

    /// With "Same copy for the same verifier", presenting twice to one
    /// verifier uses one copy, and the second consent screen says the
    /// verifier has seen the credential before.
    @MainActor
    func testCopyPolicyPerVerifier() async throws {
        let app = try await receiveWithPIN(reset: true)
        app.buttons["settings"].tap()
        let perVerifier = app.buttons["Same copy for the same verifier"]
        XCTAssertTrue(perVerifier.waitForExistence(timeout: 10))
        perVerifier.tap()

        var current = app
        for round in 0..<2 {
            let request = try await Self.fetch("request", query: [URLQueryItem(name: "format", value: "dc+sd-jwt")], method: "POST")
            current = try await presentOnce(current, link: request["link"] as! String)
            let shownBefore = current.staticTexts["shown-before"]
            if round == 0 {
                XCTAssertFalse(shownBefore.exists, "a first presentation says the verifier has seen the credential")
            } else {
                XCTAssertTrue(shownBefore.waitForExistence(timeout: 10), "the second consent screen doesn't say the verifier has seen it")
            }
            current.buttons["share"].tap()
            let status = current.staticTexts["status"]
            XCTAssertTrue(status.waitForExistence(timeout: 30))
            await fulfillment(of: [XCTNSPredicateExpectation(predicate: NSPredicate(format: "label BEGINSWITH 'Shared with'"), object: status)], timeout: 30)
        }
        let credential = current.descendants(matching: .any).matching(identifier: "credential").firstMatch
        XCTAssertTrue(credential.waitForExistence(timeout: 10))
        XCTAssertTrue(waitFor(credential, containing: "2 of 3 copies unused"), credential.label)
    }

    /// A request from a verifier the wallet doesn't trust is refused
    /// unopened, prominently: no consent screen, nothing shared.
    @MainActor
    func testUntrustedVerifierRefused() async throws {
        let request = try await Self.fetch("request", query: [URLQueryItem(name: "format", value: "dc+sd-jwt")], method: "POST")
        let app = try await launch(request: request["link"] as? String, trustVerifier: false)
        XCTAssertTrue(app.descendants(matching: .any).matching(identifier: "untrusted-verifier").firstMatch.waitForExistence(timeout: 20),
                      "no untrusted verifier screen")
        XCTAssertTrue(app.staticTexts["nothing-shared"].exists)
        XCTAssertFalse(app.buttons["share"].exists, "the consent screen opened for an untrusted verifier")
        let result = try await Self.fetch("request/\(request["id"] as! String)")
        XCTAssertNotEqual(result["status"] as? String, "done")
    }

    /// A registered verifier's registration shows on the consent screen,
    /// and a request beyond it is flagged, claim by claim.
    @MainActor
    func testRegisteredVerifier() async throws {
        var app = try await receiveWithPIN(reset: true)
        let within = try await Self.fetch("request", query: [URLQueryItem(name: "format", value: "dc+sd-jwt"), URLQueryItem(name: "registered", value: "1")], method: "POST")
        app = try await presentOnce(app, link: within["link"] as! String)
        XCTAssertTrue(reveal(app.descendants(matching: .any).matching(identifier: "registered").firstMatch, in: app, wait: 10), "the registration isn't shown")
        XCTAssertFalse(app.descendants(matching: .any).matching(identifier: "over-asking").firstMatch.exists, "a request within the registration was flagged")
        XCTAssertTrue(reveal(app.buttons["decline"], in: app))
        app.buttons["decline"].tap()

        let over = try await Self.fetch("request", query: [
            URLQueryItem(name: "format", value: "dc+sd-jwt"), URLQueryItem(name: "registered", value: "1"), URLQueryItem(name: "extra", value: "given_name"),
        ], method: "POST")
        app = try await presentOnce(app, link: over["link"] as! String)
        let flagged = app.descendants(matching: .any).matching(identifier: "over-asking").firstMatch
        XCTAssertTrue(reveal(flagged, in: app, wait: 10), "a request beyond the registration isn't flagged")
        XCTAssertTrue(flagged.label.contains("given_name"), flagged.label)
        XCTAssertTrue(reveal(app.staticTexts["disclosed-unregistered"], in: app, wait: 10), "the unregistered claim isn't marked")
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

    /// Sharing in person: the Present tab shows the QR code at once where
    /// there's Bluetooth, and on the Simulator — which has none — says so,
    /// with nothing shared.
    @MainActor
    func testShareInPerson() async throws {
        let offer = try await Self.fetch("offer", query: [URLQueryItem(name: "pin", value: "493536"), URLQueryItem(name: "mdoc", value: "1")],
                                         method: "POST")["offer"] as! String
        let app = try await launch(offer: offer)
        let pin = app.textFields["pin"]
        XCTAssertTrue(pin.waitForExistence(timeout: 20))
        pin.tap()
        pin.typeText("493536")
        app.buttons["receive"].tap()
        let status = app.staticTexts["status"]
        XCTAssertTrue(status.waitForExistence(timeout: 60))
        XCTAssertTrue(status.label.hasPrefix("Received 2"), status.label)

        app.tabBars.buttons["Present"].tap()
        let qr = app.images["in-person-qr"]
        let outcome = app.staticTexts["in-person-outcome"]
        let deadline = Date().addingTimeInterval(20)
        while !qr.exists && !outcome.exists && Date() < deadline { try await Task.sleep(for: .milliseconds(250)) }
        if outcome.exists {
            XCTAssertTrue(outcome.label.contains("Bluetooth"), outcome.label)
        } else {
            XCTAssertTrue(qr.exists, "neither the QR code nor an outcome")
        }
        app.tabBars.buttons["Wallet"].tap()
        XCTAssertTrue(app.buttons["scan"].waitForExistence(timeout: 10), "back on the wallet")
    }

    /// The Verify tab offers what to ask for; the Wallet tab is back to
    /// the credentials.
    @MainActor
    func testReaderMode() async throws {
        let app = try await launch()
        let verify = app.tabBars.buttons["Verify"]
        XCTAssertTrue(verify.waitForExistence(timeout: 10), "no Verify tab")
        verify.tap()
        let presets = app.buttons.matching(identifier: "reader-preset")
        XCTAssertTrue(presets.firstMatch.waitForExistence(timeout: 10))
        XCTAssertEqual(presets.count, 5)
        app.tabBars.buttons["Wallet"].tap()
        XCTAssertTrue(app.buttons["scan"].waitForExistence(timeout: 10), "back on the wallet")
    }
}
