import CryptoKit
import Foundation
import LocalAuthentication
import Network
import Security
import XCTest
@testable import OID4VCWallet

final class OID4VCWalletTests: XCTestCase {
    func testABIVersion() {
        XCTAssertEqual(OID4VC.abiVersion, 16)
        XCTAssertTrue(OID4VC.isTestBuild, "the tests run on the mobiletest build")
    }

    /// A misspelled key is refused, not dropped before the wallet could
    /// refuse it; the role EKUs and declined revocation roles round-trip.
    func testConfigurationDecodingIsStrict() throws {
        let good = #"{"issuer_roots":"","issuer_require_eku":"1.2.3","issuer_metadata_require_eku":"1.2.4","mdoc_issuer_require_eku":"1.0.18013.5.1.2","mdoc_issuer_roots_by_doctype":{"org.iso.18013.5.1.mDL":""},"no_revocation_check":["issuer","status"]}"#
        let config = try JSONDecoder().decode(WalletConfiguration.self, from: Data(good.utf8))
        XCTAssertEqual(config.issuers.requireEKU, "1.2.3")
        XCTAssertEqual(config.issuerMetadata.requireEKU, "1.2.4")
        XCTAssertEqual(config.issuers.mdocRequireEKU, "1.0.18013.5.1.2")
        XCTAssertEqual(config.issuers.mdocRootsByDocType, ["org.iso.18013.5.1.mDL": ""])
        XCTAssertEqual(config.revocation.declined, [.issuer, .status])
        let typo = #"{"require_trusted_mdoc_readr":true}"#
        XCTAssertThrowsError(try JSONDecoder().decode(WalletConfiguration.self, from: Data(typo.utf8)))
    }

    /// The grouped configuration keeps the flat JSON it had before the
    /// grouping: every key of a fully populated configuration decodes into
    /// its group and encodes back to the same JSON, and a default
    /// configuration encodes the same keys as before.
    func testWalletConfigurationJSONRoundTrip() throws {
        let full = #"""
        {"client_id":"c","redirect_uri":"app:/cb","issuer_roots":"IR","verifier_roots":"VR","registrar_roots":"RR",
         "mdoc_reader_roots":"MR","mdoc_reader_require_eku":true,"require_trusted_mdoc_reader":true,
         "development":true,"development_roots":"DR","locales":["de","en"],"batch_size":3,"request_refresh":true,
         "copy_policy":"per_verifier","issuance_profile":"haip","proof_key_by_jwk":true,"proof_key_by_index":true,
         "accept_x509_san_dns":true,"tls_pins":{"a.example":["pin"]},"allowed_private_hosts":["h.example"],
         "proximity_device_auth":"mac_preferred","verifier_require_eku":"1.1","registrar_require_eku":"1.2",
         "issuer_require_eku":"1.3","issuer_metadata_require_eku":"1.4",
         "status_issuers":{"https://i.example":["https://s.example"]},"require_issuer_name":true,
         "issuer_metadata_roots":"IMR","require_signed_issuer_metadata":true,"require_issuer_metadata_name":true,
         "max_issuer_metadata_age_seconds":60,"allow_foreign_iss":true,"credential_issuers":["https://i.example"],
         "allow_any_credential_issuer":true,"mdoc_issuer_roots":"MIR",
         "mdoc_issuer_roots_by_doctype":{"org.iso.18013.5.1.mDL":"X"},"mdoc_issuer_require_eku":"1.5",
         "accept_mdl_signer_without_eku":true,"crls":"C","revocation":["issuer","verifier"],"crl_issuers":"CI",
         "no_revocation_check":["status"],"crl_distribution_points":[{"url":"http://ca.example/ca.crl","issuer":"P"}],
         "crl_distribution_points_from_roots":true,"crl_require_https":true,"status_max_bytes":10,
         "identifier_list_max_bytes":11,"status_cache_max_age_seconds":12,"status_cache_dir":"/d"}
        """#
        let config = try JSONDecoder().decode(WalletConfiguration.self, from: Data(full.utf8))
        XCTAssertEqual(config.issuers.roots, "IR")
        XCTAssertEqual(config.issuers.mdocRoots, "MIR")
        XCTAssertEqual(config.issuers.statusIssuers, ["https://i.example": ["https://s.example"]])
        XCTAssertEqual(config.issuers.credentialIssuers, ["https://i.example"])
        XCTAssertTrue(config.issuers.allowAnyCredentialIssuer)
        XCTAssertEqual(config.issuerMetadata.maxAgeSeconds, 60)
        XCTAssertTrue(config.issuerMetadata.requireSigned)
        XCTAssertEqual(config.verifiers.registrarRequireEKU, "1.2")
        XCTAssertTrue(config.verifiers.requireTrustedMdocReader)
        XCTAssertEqual(config.revocation.roles, [.issuer, .verifier])
        XCTAssertEqual(config.revocation.declined, [.status])
        XCTAssertEqual(config.status.cacheMaxAgeSeconds, 12)
        XCTAssertEqual(config.status.cacheDir, "/d")
        XCTAssertEqual(config.network.allowedPrivateHosts, ["h.example"])
        XCTAssertEqual(config.issuance.profile, .haip)
        XCTAssertEqual(config.issuance.locales, ["de", "en"])
        XCTAssertEqual(config.presentation.copyPolicy, .perVerifier)
        XCTAssertEqual(config.presentation.proximityDeviceAuth, .macPreferred)
        XCTAssertEqual(config.development?.roots, "DR")
        try assertSameJSON(JSONEncoder().encode(config), Data(full.utf8))

        let fullKeys = try Set(jsonKeys(Data(full.utf8)))
        XCTAssertEqual(try Set(jsonKeys(JSONEncoder().encode(WalletConfiguration()))), fullKeys.subtracting(["status_cache_dir"]))
        let production = try JSONSerialization.jsonObject(with: JSONEncoder().encode(WalletConfiguration())) as? [String: Any]
        XCTAssertEqual(production?["development"] as? Bool, false)
        XCTAssertEqual(production?["development_roots"] as? String, "")
    }

    /// The reader's grouped configuration keeps its flat JSON, as the
    /// wallet's does; `require_mdl_signer_eku`, which did nothing, is
    /// still read, and no longer written.
    func testReaderConfigurationJSONRoundTrip() throws {
        let full = #"""
        {"issuer_roots":"IR","reader_key_id":"k","reader_chain":"CH","max_clock_skew_seconds":30,
         "accept_mdl_signer_without_eku":true,"issuer_roots_by_doctype":{"org.iso.18013.5.1.mDL":"X"},"crls":"C",
         "revocation":["issuer"],"crl_issuers":"CI","no_revocation_check":["status"],"any_issuer_for_any_type":true,
         "development":true,"status":"check","crl_distribution_points":[{"url":"http://ca.example/ca.crl","issuer":"P"}],
         "crl_distribution_points_from_roots":true,"crl_require_https":true,"development_roots":"DR",
         "status_max_bytes":10,"identifier_list_max_bytes":11,"status_cache_max_age_seconds":12,"status_cache_dir":"/d"}
        """#
        let config = try JSONDecoder().decode(ProximityReaderConfiguration.self, from: Data(full.utf8))
        XCTAssertEqual(config.issuers.roots, "IR")
        XCTAssertEqual(config.issuers.rootsByDocType, ["org.iso.18013.5.1.mDL": "X"])
        XCTAssertTrue(config.issuers.anyIssuerForAnyType)
        XCTAssertTrue(config.issuers.acceptMDLSignerWithoutEKU)
        XCTAssertEqual(config.readerAuthentication?.keyID, "k")
        XCTAssertEqual(config.readerAuthentication?.chain, "CH")
        XCTAssertEqual(config.maxClockSkewSeconds, 30)
        XCTAssertEqual(config.revocation.roles, [.issuer])
        XCTAssertEqual(config.revocation.declined, [.status])
        XCTAssertTrue(config.revocation.requireHTTPS)
        XCTAssertEqual(config.status.maxBytes, 10)
        XCTAssertEqual(config.statusCheck, .check)
        XCTAssertEqual(config.development?.roots, "DR")
        try assertSameJSON(JSONEncoder().encode(config), Data(full.utf8))

        var old = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(full.utf8)) as? [String: Any])
        old["require_mdl_signer_eku"] = false
        let withOld = try JSONDecoder().decode(ProximityReaderConfiguration.self, from: JSONSerialization.data(withJSONObject: old))
        try assertSameJSON(JSONEncoder().encode(withOld), Data(full.utf8))

        let fullKeys = try Set(jsonKeys(Data(full.utf8)))
        XCTAssertEqual(try Set(jsonKeys(JSONEncoder().encode(ProximityReaderConfiguration(issuers: .init(roots: ""))))),
                       fullKeys.subtracting(["reader_key_id", "reader_chain", "max_clock_skew_seconds", "status", "status_cache_dir"]))
    }

    /// `require_mdl_signer_eku` alone, true or false, is ignored; with
    /// `accept_mdl_signer_without_eku` it's refused, as the library
    /// refused it.
    func testReaderConfigurationRefusesBothSignerEKUOptions() throws {
        for required in [true, false] {
            let alone = try JSONDecoder().decode(ProximityReaderConfiguration.self,
                                                 from: Data(#"{"issuer_roots":"IR","require_mdl_signer_eku":\#(required)}"#.utf8))
            XCTAssertNil(try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(alone)) as? [String: Any])["require_mdl_signer_eku"])
        }
        XCTAssertNoThrow(try JSONDecoder().decode(ProximityReaderConfiguration.self, from: Data(
            #"{"issuer_roots":"IR","require_mdl_signer_eku":false,"accept_mdl_signer_without_eku":true}"#.utf8)))
        let both = #"{"issuer_roots":"IR","require_mdl_signer_eku":true,"accept_mdl_signer_without_eku":true}"#
        XCTAssertThrowsError(try JSONDecoder().decode(ProximityReaderConfiguration.self, from: Data(both.utf8))) {
            guard case DecodingError.dataCorrupted(let context) = $0 else { return XCTFail("\($0)") }
            XCTAssertEqual(context.debugDescription, "require_mdl_signer_eku and accept_mdl_signer_without_eku can't both be set")
        }
    }

    private func jsonKeys(_ data: Data) throws -> [String] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any]).map(\.key)
    }

    private func assertSameJSON(_ got: Data, _ want: Data, file: StaticString = #filePath, line: UInt = #line) throws {
        let g = try XCTUnwrap(JSONSerialization.jsonObject(with: got) as? NSDictionary)
        let w = try XCTUnwrap(JSONSerialization.jsonObject(with: want) as? NSDictionary)
        XCTAssertEqual(g, w, file: file, line: line)
    }

    func testParseRequestLink() async throws {
        let link = try await OID4VC.parseRequestLink(
            "openid4vp://?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Fverifier.example%2Fr%2F1")
        XCTAssertEqual(link, RequestLink(clientID: "x509_hash:abc", requestURI: "https://verifier.example/r/1", requestURIMethod: "get"))
    }

    func testGoErrorsBecomeWalletErrors() async {
        do {
            _ = try await OID4VC.parseRequestLink("openid4vp://?client_id=x")
            XCTFail("a link without request_uri was accepted")
        } catch let error as WalletError {
            XCTAssertEqual(error.code, .invalidInput)
            XCTAssertFalse(error.message.isEmpty)
            XCTAssertNotNil(error.errorDescription)
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func testWalletErrorParsing() {
        func parse(_ text: String) -> WalletError {
            WalletError(NSError(domain: "go", code: 1, userInfo: [NSLocalizedDescriptionKey: text]))
        }
        let pin = parse("[protocol:invalid_grant] walletflow: token: wrong tx_code")
        XCTAssertEqual(pin.code, .protocolError)
        XCTAssertEqual(pin.protocolError, "invalid_grant")
        XCTAssertTrue(pin.isRetryable)
        XCTAssertEqual(pin.localizedDescription, "That code or PIN wasn't accepted.")
        XCTAssertEqual(pin.description, "[protocol:invalid_grant] walletflow: token: wrong tx_code")

        let network = parse("[network] dial tcp: refused")
        XCTAssertEqual(network.code, .network)
        XCTAssertNil(network.protocolError)
        XCTAssertTrue(network.isRetryable)

        XCTAssertTrue(parse("[unavailable] the issuer refused the request (HTTP 503)").isRetryable)
        XCTAssertTrue(parse("[protocol:invalid_nonce] stale").isRetryable)
        XCTAssertFalse(parse("[protocol:invalid_client] no").isRetryable)
        XCTAssertFalse(parse("[delivery_unknown] maybe").isRetryable)
        XCTAssertFalse(parse("[credential_denied] no").isRetryable)
        let plain = parse("no code")
        XCTAssertEqual(plain.code, .internalError)
        XCTAssertEqual(plain.message, "no code")
    }

    /// A Swift error thrown in a callback reaches Go, which reports it as
    /// a platform error carrying the Swift error's message.
    func testSwiftCallbackErrorsReachGo() async throws {
        do {
            _ = try await OID4VC.checkKeyStore(Misbehaving(signError: "the user cancelled Face ID"))
            XCTFail("a refusing store passed")
        } catch let error as WalletError {
            XCTAssertEqual(error.code, .platform)
            XCTAssertTrue(error.message.contains("the user cancelled Face ID"), error.message)
        }
        do {
            _ = try await OID4VC.checkKeyStore(Misbehaving(createError: "no enclave"))
            XCTFail("a store that can't create keys passed")
        } catch let error as WalletError {
            XCTAssertEqual(error.code, .platform)
            XCTAssertTrue(error.message.contains("no enclave"), error.message)
        }
    }

    func testCheckKeyStoreSoftwareInMemory() async throws {
        let checked = try await OID4VC.checkKeyStore(KeychainKeyStore(options: .init(secureEnclave: false, persistent: false)))
        XCTAssertEqual(checked, KeyPurpose.allCases)
    }

    /// Keys kept in the Keychain: found again by a new store, listed, and
    /// swept. (Hostless iOS Simulator tests have no Keychain.)
    func testKeychainKeysAndSweep() async throws {
        #if targetEnvironment(simulator)
        throw XCTSkip("the iOS Simulator's Keychain needs a signed host app")
        #else
        let options = KeychainKeyStore.Options(secureEnclave: false, persistent: true, holderUserPresence: false,
                                               tagPrefix: "org.idfoundry.oid4vcgo.test.\(UUID()).")
        let checked = try await OID4VC.checkKeyStore(KeychainKeyStore(options: options))
        XCTAssertEqual(checked.count, 3)

        let store = KeychainKeyStore(options: options)
        let kept = try store.createKey(purpose: .holder)
        let orphan = try store.createKey(purpose: .dpop)
        let again = KeychainKeyStore(options: options)
        XCTAssertNotNil(try again.publicKey(id: kept))
        XCTAssertFalse(try again.sign(id: kept, digest: Data(repeating: 1, count: 32)).isEmpty)
        XCTAssertEqual(Set(try again.keyIDs()), [kept, orphan])
        XCTAssertEqual(try again.deleteKeys(except: [kept]), 1)
        XCTAssertNil(try again.publicKey(id: orphan))
        XCTAssertEqual(try again.keyIDs(), [kept])
        try again.deleteKey(id: kept)
        XCTAssertEqual(try again.keyIDs(), [])
        #endif
    }

    /// A sweep deletes only the keys a KeychainKeyStore made: another of
    /// the app's keys under the same tag prefix is kept.
    func testKeychainSweepKeepsKeysItDidntMake() throws {
        #if targetEnvironment(simulator)
        throw XCTSkip("the iOS Simulator's Keychain needs a signed host app")
        #else
        let prefix = "org.idfoundry.oid4vcgo.test.\(UUID())."
        let store = KeychainKeyStore(options: .init(secureEnclave: false, persistent: true, holderUserPresence: false, tagPrefix: prefix))
        let orphan = try store.createKey(purpose: .dpop)
        // Another of the app's keys under the prefix: one without the
        // store's label.
        let foreign = try store.createKey(purpose: .holder)
        defer { try? store.deleteKey(id: foreign) }
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data((prefix + foreign).utf8),
        ]
        XCTAssertEqual(SecItemUpdate(query as CFDictionary, [kSecAttrLabel as String: "the app's own key"] as CFDictionary), errSecSuccess)
        XCTAssertEqual(Set(try store.keyIDs()), [orphan, foreign])
        XCTAssertEqual(try store.deleteKeys(except: []), 1)
        XCTAssertEqual(try store.keyIDs(), [foreign], "the sweep deleted a key it didn't make")
        #endif
    }

    /// Stores whose prefixes extend another's, with a separator or
    /// without, keep their keys from its sweep, and it keeps its own from
    /// theirs: each lists and sweeps only its prefix and a UUID.
    func testNestedPrefixesKeepEachOthersKeys() throws {
        #if targetEnvironment(simulator)
        throw XCTSkip("the iOS Simulator's Keychain needs a signed host app")
        #else
        let prefix = "org.idfoundry.oid4vcgo.test.\(UUID())."
        func store(_ prefix: String) -> KeychainKeyStore {
            KeychainKeyStore(options: .init(secureEnclave: false, persistent: true, holderUserPresence: false, tagPrefix: prefix))
        }
        let keys = store(prefix)
        let longer = ["b.", "b-", "b"].map { store(prefix + $0) }
        defer { for s in longer + [keys] { _ = try? s.deleteKeys(except: []) } }
        let theirs = try longer.map { try $0.createKey(purpose: .dpop) }
        _ = try keys.createKey(purpose: .dpop)
        XCTAssertEqual(try keys.deleteKeys(except: []), 1)
        for (s, id) in zip(longer, theirs) { XCTAssertEqual(try s.keyIDs(), [id]) }
        let mine = try keys.createKey(purpose: .dpop)
        for s in longer { XCTAssertEqual(try s.deleteKeys(except: []), 1) }
        XCTAssertEqual(try keys.keyIDs(), [mine])
        XCTAssertFalse(KeychainKeyStore.isKeyID(mine.lowercased()))
        #endif
    }

    /// A sweep refuses a store whose tag prefix is empty, or overlaps the
    /// Wallet Provider registration key's.
    func testSweepRefusesReservedPrefixes() throws {
        let registration = HttpWalletProvider.registrationKeyTagPrefix
        for prefix in ["", registration, registration + "other.", "org.idfoundry.oid4vcgo.", "org.idfoundry.", "o"] {
            XCTAssertNotNil(Wallet.sweepRefusal(tagPrefix: prefix), "prefix \(prefix) accepted")
        }
        for prefix in [KeychainKeyStore.Options().tagPrefix, "com.example.wallet.keys.", "org.idfoundry.oid4vcgo.key.test."] {
            XCTAssertNil(Wallet.sweepRefusal(tagPrefix: prefix), "prefix \(prefix) refused")
        }
        let empty = KeychainKeyStore(options: .init(secureEnclave: false, persistent: false, tagPrefix: ""))
        _ = try empty.createKey(purpose: .dpop)
        XCTAssertThrowsError(try empty.deleteKeys(except: []))
        XCTAssertEqual(try empty.keyIDs().count, 1)
    }

    /// Keys in the Secure Enclave — simulated by the iOS Simulator; a
    /// real device needs the demo app.
    func testCheckKeyStoreSecureEnclave() async throws {
        #if targetEnvironment(simulator)
        let store = KeychainKeyStore(options: .init(secureEnclave: true, persistent: false, holderUserPresence: false))
        let checked = try await OID4VC.checkKeyStore(store)
        XCTAssertEqual(checked.count, 3)
        #else
        throw XCTSkip("Secure Enclave keys need the iOS Simulator or a signed app")
        #endif
    }

    /// A holder key agrees the secret the peer computes, and still signs;
    /// instance and DPoP keys never agree keys.
    func testHolderKeyAgreesKeys() throws {
        try checkAgreement(KeychainKeyStore(options: .init(secureEnclave: false, persistent: false)))
    }

    /// The same in the Secure Enclave — simulated by the iOS Simulator; a
    /// real device needs the demo app.
    func testSecureEnclaveHolderKeyAgreesKeys() throws {
        #if targetEnvironment(simulator)
        try checkAgreement(KeychainKeyStore(options: .init(secureEnclave: true, persistent: false, holderUserPresence: false)))
        #else
        throw XCTSkip("Secure Enclave keys need the iOS Simulator or a signed app")
        #endif
    }

    func checkAgreement(_ store: KeychainKeyStore) throws {
        let id = try store.createKey(purpose: .holder)
        let peer = P256.KeyAgreement.PrivateKey()
        let z = try store.agree(id: id, peerPublicKey: peer.publicKey.x963Representation)
        let holder = try P256.KeyAgreement.PublicKey(x963Representation: XCTUnwrap(try store.publicKey(id: id)))
        let want = try peer.sharedSecretFromKeyAgreement(with: holder).withUnsafeBytes { Data($0) }
        XCTAssertEqual(z, want)
        XCTAssertEqual(z.count, 32)
        XCTAssertFalse(try store.sign(id: id, digest: Data(repeating: 1, count: 32)).isEmpty)
        let dpop = try store.createKey(purpose: .dpop)
        XCTAssertThrowsError(try store.agree(id: dpop, peerPublicKey: peer.publicKey.x963Representation)) {
            XCTAssertTrue($0 is KeyAgreementUnsupported, "\($0)")
        }
        XCTAssertThrowsError(try store.agree(id: id, peerPublicKey: Data([4, 1, 2])))
        // A point off the curve: the peer's x with y + 1.
        var offCurve = peer.publicKey.x963Representation
        offCurve[64] ^= 1
        XCTAssertThrowsError(try store.agree(id: id, peerPublicKey: offCurve)) {
            XCTAssertTrue($0 is StoreError, "\($0)")
        }
    }

    /// The peer-point check on its own: checkAgreement can't tell it from
    /// SecKeyCreateWithData, which refuses the off-curve point itself on
    /// macOS.
    func testPeerPointMustBeOnTheCurve() {
        let point = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        XCTAssertTrue(KeychainKeyStore.isUncompressedP256Point(point))
        var offCurve = point
        offCurve[64] ^= 1
        XCTAssertFalse(KeychainKeyStore.isUncompressedP256Point(offCurve))
        XCTAssertFalse(KeychainKeyStore.isUncompressedP256Point(P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation))
        XCTAssertFalse(KeychainKeyStore.isUncompressedP256Point(Data([4]) + Data(repeating: 0, count: 64)))
    }

    func testCheckKeyAgreement() async throws {
        let store = KeychainKeyStore(options: .init(secureEnclave: false, persistent: false))
        let supported = try await OID4VC.checkKeyAgreement(store, store)
        XCTAssertTrue(supported)
        struct Refusing: KeyAgreement {
            func agree(id: String, peerPublicKey: Data) throws -> Data { throw KeyAgreementUnsupported("signing only") }
        }
        let unsupported = try await OID4VC.checkKeyAgreement(store, Refusing())
        XCTAssertFalse(unsupported)
    }

    func testMemoryKeySweep() throws {
        let store = KeychainKeyStore(options: .init(secureEnclave: false, persistent: false))
        let a = try store.createKey(purpose: .instance)
        let b = try store.createKey(purpose: .holder)
        XCTAssertEqual(try store.deleteKeys(except: [b]), 1)
        XCTAssertNil(try store.publicKey(id: a))
        XCTAssertNotNil(try store.publicKey(id: b))
    }

    /// The async provider bridge: Go blocks its thread while a Swift
    /// async provider answers.
    func testAsyncProviderBridge() throws {
        struct Slow: WalletProvider {
            func walletAttestation(clientID: String, instanceKey: Data) async throws -> String {
                try await Task.sleep(nanoseconds: 50 * 1_000_000)
                return "wa-\(clientID)-\(instanceKey.count)"
            }
            func keyAttestation(instanceKey: Data, keys: [Data], nonce: String) async throws -> String {
                if nonce == "fail" { throw StoreError("provider down") }
                return "ka-\(instanceKey.count)-\(keys.count)-\(nonce)"
            }
        }
        let adapter = WalletProviderAdapter(Slow())
        let instance = Data("{\"kty\":\"EC\"}".utf8)
        XCTAssertEqual(String(decoding: try adapter.walletAttestation("c", instanceKeyJWK: instance), as: UTF8.self), "wa-c-12")
        XCTAssertEqual(String(decoding: try adapter.keyAttestation(instance, keysJWK: Data("[{\"a\":1},{\"b\":2}]".utf8), nonce: "n"), as: UTF8.self), "ka-12-2-n")
        XCTAssertThrowsError(try adapter.keyAttestation(instance, keysJWK: Data("[]".utf8), nonce: "fail"))
        XCTAssertThrowsError(try adapter.keyAttestation(instance, keysJWK: Data("{}".utf8), nonce: "n"), "keys that aren't an array")

        // A provider's URLError reaches Go marked as a network failure.
        struct Offline: WalletProvider {
            func walletAttestation(clientID _: String, instanceKey _: Data) async throws -> String { throw URLError(.notConnectedToInternet) }
            func keyAttestation(instanceKey _: Data, keys _: [Data], nonce _: String) async throws -> String { "" }
        }
        XCTAssertThrowsError(try WalletProviderAdapter(Offline()).walletAttestation("c", instanceKeyJWK: Data("{}".utf8))) { error in
            XCTAssertTrue(error.localizedDescription.hasPrefix("[network] "), error.localizedDescription)
        }

        // A refusal with the protocol's error code reaches Go marked with
        // it; one without a code, unmarked.
        struct Refusing: WalletProvider {
            let code: String?
            func walletAttestation(clientID _: String, instanceKey _: Data) async throws -> String {
                throw WalletProviderRefusedError(status: 403, error: code, description: nil, path: "/v1/wallet-attestation")
            }
            func keyAttestation(instanceKey _: Data, keys _: [Data], nonce _: String) async throws -> String { "" }
        }
        XCTAssertThrowsError(try WalletProviderAdapter(Refusing(code: "instance_revoked")).walletAttestation("c", instanceKeyJWK: Data("{}".utf8))) { error in
            XCTAssertEqual(error.localizedDescription, "[refused:instance_revoked] the Wallet Provider refused /v1/wallet-attestation: HTTP 403 instance_revoked")
        }
        XCTAssertThrowsError(try WalletProviderAdapter(Refusing(code: nil)).walletAttestation("c", instanceKeyJWK: Data("{}".utf8))) { error in
            XCTAssertEqual(error.localizedDescription, "the Wallet Provider refused /v1/wallet-attestation: HTTP 403")
        }
    }

    /// The holder cancelling a key's prompt reaches Go marked as a
    /// cancellation; another failure, unmarked.
    func testHolderCancellationIsMarked() {
        let userCancel = NSError(domain: NSOSStatusErrorDomain, code: Int(errSecUserCanceled))
        let laCancel = NSError(domain: LAErrorDomain, code: LAError.Code.userCancel.rawValue)
        for error in [userCancel, laCancel, CancellationError() as Error] {
            XCTAssertTrue(isHolderCancellation(error), "\(error)")
            XCTAssertThrowsError(try markingHolderCancellation { () throws -> Int in throw error }) { thrown in
                XCTAssertTrue(thrown.localizedDescription.hasPrefix("[cancelled] "), thrown.localizedDescription)
            }
        }
        let other = NSError(domain: NSOSStatusErrorDomain, code: Int(errSecAuthFailed))
        XCTAssertFalse(isHolderCancellation(other))
        XCTAssertFalse(isHolderCancellation(NSError(domain: LAErrorDomain, code: LAError.Code.authenticationFailed.rawValue)))
        XCTAssertThrowsError(try markingHolderCancellation { () throws -> Int in throw other }) { thrown in
            XCTAssertFalse(thrown.localizedDescription.hasPrefix("[cancelled]"), thrown.localizedDescription)
        }
    }

    /// A Wallet Provider's refusal, the holder's cancellation and a TLS
    /// pin mismatch each have a sentence for the holder.
    func testHolderFacingTextForProviderRefusalsAndPins() {
        func parse(_ text: String) -> WalletError {
            WalletError(NSError(domain: "go", code: 1, userInfo: [NSLocalizedDescriptionKey: text]))
        }
        let suspended = parse("[platform:instance_not_active] wallet attestation: the Wallet Provider refused")
        XCTAssertEqual(suspended.code, .platform)
        XCTAssertEqual(suspended.protocolError, "instance_not_active")
        XCTAssertEqual(suspended.localizedDescription, "This wallet is suspended by its provider. Contact them, or try again later.")
        XCTAssertNotEqual(parse("[platform:instance_revoked] x").localizedDescription, parse("[platform] x").localizedDescription)
        XCTAssertNotEqual(parse("[platform:invalid_signed_request] x").localizedDescription, parse("[platform] x").localizedDescription)
        XCTAssertEqual(parse("[platform:evidence_rejected] x").localizedDescription, "The wallet's provider refused the request.")
        XCTAssertEqual(parse("[cancelled] sign with key: the holder cancelled").code, .cancelled)
        XCTAssertEqual(parse("[tls_pin] pin mismatch").localizedDescription, "The service's identity couldn't be confirmed, so nothing was sent to it.")
    }
}

/// A key store that fails as it's told to.
final class Misbehaving: KeyStore, @unchecked Sendable {
    let inner = KeychainKeyStore(options: .init(secureEnclave: false, persistent: false))
    let createError: String?
    let signError: String?

    init(createError: String? = nil, signError: String? = nil) {
        self.createError = createError
        self.signError = signError
    }

    func createKey(purpose: KeyPurpose) throws -> String {
        if let createError { throw StoreError(createError) }
        return try inner.createKey(purpose: purpose)
    }

    func publicKey(id: String) throws -> Data? { try inner.publicKey(id: id) }

    func sign(id: String, digest: Data) throws -> Data {
        if let signError { throw StoreError(signError) }
        return try inner.sign(id: id, digest: digest)
    }

    func deleteKey(id: String) throws { try inner.deleteKey(id: id) }
}

func base64url(_ s: String) throws -> Data {
    var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    b += String(repeating: "=", count: (4 - b.count % 4) % 4)
    guard let d = Data(base64Encoded: b) else { throw WalletError(NSError(domain: "test", code: 0)) }
    return d
}

final class SilentServer: @unchecked Sendable {
    final class Connections: @unchecked Sendable {
        let lock = NSLock()
        var all: [NWConnection] = []
        func add(_ c: NWConnection) { lock.withLock { all.append(c) } }
    }

    let listener: NWListener
    let port: UInt16
    private let connections = Connections()

    init() throws {
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: params)
        let ready = DispatchSemaphore(value: 0)
        let connections = self.connections
        listener.stateUpdateHandler = { if case .ready = $0 { ready.signal() } }
        listener.newConnectionHandler = { c in
            c.start(queue: .global())
            connections.add(c)
        }
        listener.start(queue: .global())
        guard ready.wait(timeout: .now() + 5) == .success, let p = listener.port?.rawValue else {
            throw WalletError(NSError(domain: "test", code: 0, userInfo: [NSLocalizedDescriptionKey: "listener didn't start"]))
        }
        port = p
    }

    func stop() {
        connections.lock.withLock { connections.all.forEach { $0.cancel() } }
        listener.cancel()
    }
}
