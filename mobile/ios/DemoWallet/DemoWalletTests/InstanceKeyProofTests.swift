import CryptoKit
import OID4VCWallet
import XCTest
@testable import DemoWallet

/// The passport-vdc demo provider's instance_key_proof, against the
/// vector its walletprovider's TestInstanceKeyProofVector pins: RFC 7515
/// Appendix A.3's key signed the proof over the keys of RFC 6979
/// Appendix A.2.5 and RFC 7517 Appendix A.1.
final class InstanceKeyProofTests: XCTestCase {
    private let instanceJWK = Data(#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#.utf8)
    private let keys = [
        #"{"kty":"EC","crv":"P-256","x":"YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y","y":"eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk"}"#,
        #"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#,
    ].map { Data($0.utf8) }
    private let nonce = "c_nonce-1"

    func testBuildsTheProvidersMessage() throws {
        let message = try InstanceKeyProof.message(nonce: nonce, keys: keys)
        XCTAssertEqual(String(decoding: message, as: UTF8.self),
                       "passport-vdc instance key proof\nc_nonce-1\nDOvxvJiAdIqVWIkFt5hDtCunXLF0BV4-JGv4f-ALSm0\ncn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s")
    }

    /// The vector's proof, which the provider accepts, is a DER signature
    /// over the message's SHA-256, as CryptoKit checks it: the form
    /// `sign` makes.
    func testVerifiesTheVectorsProof() throws {
        let proof = "MEYCIQD3hKubHciPPGC2x6WZLtuhc58iY5pssh591RVz9e33KAIhANKO1vLKLem_45EFQHIa2Hpz3xmKQM62tQKv-7HWgMqU"
        let key = try P256.Signing.PublicKey(x963Representation: InstanceKeyProof.uncompressedPoint(instanceJWK))
        XCTAssertTrue(try key.isValidSignature(signature(proof), for: InstanceKeyProof.message(nonce: nonce, keys: keys)))
    }

    /// The store's instance key signs, found by its public key among the
    /// store's keys.
    func testSignsWithTheStoresInstanceKey() throws {
        let store = memoryStore()
        _ = try store.createKey(purpose: .holder)
        let point = try XCTUnwrap(store.publicKey(id: store.createKey(purpose: .instance)))
        let proof = try InstanceKeyProof.sign(nonce: nonce, keys: keys, instanceKey: jwk(point), in: store)
        XCTAssertNil(proof.rangeOfCharacter(from: CharacterSet(charactersIn: "+/=")), "the proof isn't unpadded base64url")
        let key = try P256.Signing.PublicKey(x963Representation: point)
        XCTAssertTrue(try key.isValidSignature(signature(proof), for: InstanceKeyProof.message(nonce: nonce, keys: keys)))
    }

    func testRefusesAnInstanceKeyTheStoreDoesntHold() throws {
        let store = memoryStore()
        _ = try store.createKey(purpose: .instance)
        XCTAssertThrowsError(try InstanceKeyProof.sign(nonce: nonce, keys: keys, instanceKey: instanceJWK, in: store))
    }

    private func memoryStore() -> KeychainKeyStore {
        KeychainKeyStore(options: .init(secureEnclave: false, persistent: false, holderUserPresence: false))
    }

    private func jwk(_ point: Data) -> Data {
        let x = InstanceKeyProof.base64URL(point[1...32]), y = InstanceKeyProof.base64URL(point[33...])
        return Data(#"{"kty":"EC","crv":"P-256","x":"\#(x)","y":"\#(y)"}"#.utf8)
    }

    private func signature(_ proof: String) throws -> P256.Signing.ECDSASignature {
        try P256.Signing.ECDSASignature(derRepresentation: XCTUnwrap(InstanceKeyProof.base64URLDecoded(proof)))
    }
}
