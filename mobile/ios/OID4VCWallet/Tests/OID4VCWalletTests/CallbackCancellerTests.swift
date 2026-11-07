import Foundation
import Mobile
import XCTest
@testable import OID4VCWallet

/// A key store whose holder keys, while prompting, wait in `sign` for the
/// holder, as one showing the Face ID sheet does: until answered, or until
/// `cancelKeyUse` dismisses the sheet.
final class PromptingKeyStore: KeyStore, @unchecked Sendable {
    let keys = KeychainKeyStore(options: .init(secureEnclave: false, persistent: false))
    private let lock = NSLock()
    private var holderKeys: Set<String> = []
    private var sheets: [String: DispatchSemaphore] = [:]
    private var dismissed: Set<String> = []
    private(set) var cancelled: [String] = []
    var prompting = false
    let shown = DispatchSemaphore(value: 0)

    func createKey(purpose: KeyPurpose) throws -> String {
        let id = try keys.createKey(purpose: purpose)
        if purpose == .holder { lock.withLock { _ = holderKeys.insert(id) } }
        return id
    }

    func publicKey(id: String) throws -> Data? { try keys.publicKey(id: id) }

    func sign(id: String, digest: Data) throws -> Data {
        let sheet = DispatchSemaphore(value: 0)
        let prompts = lock.withLock { () -> Bool in
            guard prompting && holderKeys.contains(id) else { return false }
            sheets[id] = sheet
            return true
        }
        if prompts {
            shown.signal()
            sheet.wait()
            let wasDismissed = lock.withLock { () -> Bool in
                sheets[id] = nil
                return dismissed.remove(id) != nil
            }
            if wasDismissed { throw StoreError("the holder wasn't authenticated: cancelled") }
        }
        return try keys.sign(id: id, digest: digest)
    }

    func deleteKey(id: String) throws { try keys.deleteKey(id: id) }

    var isDurable: Bool { true }

    func cancelKeyUse(id: String) {
        lock.withLock {
            cancelled.append(id)
            if let sheet = sheets[id] {
                dismissed.insert(id)
                sheets[id] = nil
                sheet.signal()
            }
        }
    }

    func cancels() -> [String] { lock.withLock { cancelled } }
}

final class CallbackCancellerTests: XCTestCase {
    func testWaitsRunAndCancel() {
        let waits = CancellableWaits()
        XCTAssertEqual(waits.run("key", cancel: {}) { "signed" }, "signed")
        XCTAssertEqual(waits.count, 0)
        // Nothing waiting: nothing to cancel.
        waits.cancel("key")

        let sheet = DispatchSemaphore(value: 0)
        let ended = Locked(initialState: false)
        DispatchQueue.global().async {
            while waits.count == 0 { usleep(1000) }
            waits.cancel("other")
            XCTAssertFalse(ended.withLock { $0 })
            waits.cancel("key")
        }
        waits.run("key", cancel: { ended.withLock { $0 = true }; sheet.signal() }) { sheet.wait() }
        XCTAssertTrue(ended.withLock { $0 })
        XCTAssertEqual(waits.count, 0)
    }

    func testKeychainKeyStoreCancelWithNothingWaiting() throws {
        let store = KeychainKeyStore(options: .init(secureEnclave: false, persistent: false))
        let id = try store.createKey(purpose: .holder)
        store.cancelKeyUse(id: id)
        XCTAssertFalse(try store.sign(id: id, digest: Data(repeating: 1, count: 32)).isEmpty)
    }

    func testKeyStoreDefaultIgnoresCancel() {
        struct Store: KeyStore {
            func createKey(purpose: KeyPurpose) throws -> String { "id" }
            func publicKey(id: String) throws -> Data? { nil }
            func sign(id: String, digest: Data) throws -> Data { Data() }
            func deleteKey(id: String) throws {}
        }
        Store().cancelKeyUse(id: "id")
        CallbackCancellerAdapter(Store(), nil).cancelProvider(Data("{}".utf8))
    }

    func testCancellerStopsTheProvider() throws {
        struct Provider: WalletProvider {
            func walletAttestation(clientID: String, instanceKey: Data) async throws -> String {
                try await Task.sleep(nanoseconds: 60_000_000_000)
                return "jwt"
            }
            func keyAttestation(instanceKey: Data, keys: [Data], nonce: String) async throws -> String { "jwt" }
        }
        let wp = WalletProviderAdapter(Provider())
        let canceller = CallbackCancellerAdapter(PromptingKeyStore(), wp)
        let jwk = Data(#"{"kty":"EC"}"#.utf8)
        DispatchQueue.global().async {
            while wp.calls.count == 0 { usleep(1000) }
            canceller.cancelProvider(jwk)
        }
        let start = Date()
        XCTAssertThrowsError(try wp.walletAttestation("client", instanceKeyJWK: jwk))
        XCTAssertLessThan(Date().timeIntervalSince(start), 10)
    }

    /// Cancelling a presentation's Task while its holder key's sheet shows
    /// dismisses the sheet, through the CallbackCanceller, and the call
    /// ends at once, sending nothing; the holder can try again.
    func testCancelDismissesHolderPrompt() async throws {
        let env = try TestEnv()
        defer { env.close() }
        let keys = PromptingKeyStore()
        let w = try Wallet(configuration: try env.configuration, keys: KeyStoreAdapter(keys),
                           credentials: CredentialStoreAdapter(InMemoryCredentialStore()), provider: env.env.provider())
        let received = try await SessionTests.receive(env, w)
        let sdjwt = received.credentials.first { $0.format == "dc+sd-jwt" }!.id

        let req = try env.request()
        let p = try await w.startPresentation(request: req.link)
        keys.prompting = true
        let selection: Presentation.Selection = ["pid": [sdjwt]]
        let task = Task { try await p.respond(selection: selection) }
        let shown = keys.shown
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            DispatchQueue.global().async {
                shown.wait()
                cont.resume()
            }
        }
        let start = Date()
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("the cancelled presentation was sent")
        } catch let e as WalletError {
            XCTAssertEqual(e.code, .cancelled)
        } catch is CancellationError {
            // The Task's own cancellation.
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 10)
        XCTAssertFalse(keys.cancels().isEmpty)
        XCTAssertNotEqual(try env.result(req.id)["status"] as? String, "done")

        keys.prompting = false
        _ = try await p.respond(selection: selection)
        XCTAssertEqual(try env.result(req.id)["status"] as? String, "done")
    }
}
