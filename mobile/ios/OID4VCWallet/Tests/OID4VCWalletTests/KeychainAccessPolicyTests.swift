import Security
import XCTest
@testable import OID4VCWallet

/// What guards each key KeychainKeyStore makes: its access control's
/// flags, when it's accessible, and its access group.
final class KeychainAccessPolicyTests: XCTestCase {
    private typealias Options = KeychainKeyStore.Options

    func testDefaultHolderKeyNeedsPresenceAndAPasscode() {
        let policy = KeychainKeyStore.accessPolicy(purpose: .holder, options: Options())
        XCTAssertEqual(policy.flags, [.privateKeyUsage, .userPresence])
        XCTAssertEqual(policy.accessible, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)
        XCTAssertNil(policy.accessGroup)
    }

    func testDefaultSilentKeysNeedTheDeviceUnlocked() {
        for purpose in [KeyPurpose.instance, .dpop] {
            let policy = KeychainKeyStore.accessPolicy(purpose: purpose, options: Options(holderAccessGroup: "TEAM.group"))
            XCTAssertEqual(policy.flags, [.privateKeyUsage], "\(purpose)")
            XCTAssertEqual(policy.accessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, "\(purpose)")
            // Only holder keys are shared with an extension.
            XCTAssertNil(policy.accessGroup, "\(purpose)")
        }
    }

    func testHolderKeyInTheSharedGroup() {
        let policy = KeychainKeyStore.accessPolicy(purpose: .holder, options: Options(holderAccessGroup: "TEAM.group"))
        XCTAssertEqual(policy.accessGroup, "TEAM.group")
    }

    func testSoftwareKeyWithoutPresenceHasNoAccessControl() {
        let policy = KeychainKeyStore.accessPolicy(
            purpose: .holder, options: Options(secureEnclave: false, holderUserPresence: false))
        XCTAssertEqual(policy.flags, [])
        // Set as the key's own accessibility on iOS instead.
        XCTAssertEqual(policy.accessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
    }

    func testEveryCombination() {
        for purpose in KeyPurpose.allCases {
            for secureEnclave in [false, true] {
                for presence in [false, true] {
                    for group in [nil, "TEAM.group"] as [String?] {
                        for persistent in [false, true] {
                            let options = Options(secureEnclave: secureEnclave, persistent: persistent,
                                                  holderUserPresence: presence, holderAccessGroup: group)
                            let policy = KeychainKeyStore.accessPolicy(purpose: purpose, options: options)
                            let name = "\(purpose) enclave=\(secureEnclave) presence=\(presence) group=\(group ?? "nil") persistent=\(persistent)"
                            let isHolder = purpose == .holder
                            XCTAssertEqual(policy.flags.contains(.privateKeyUsage), secureEnclave, name)
                            XCTAssertEqual(policy.flags.contains(.userPresence), isHolder && presence, name)
                            XCTAssertEqual(policy.flags.subtracting([.privateKeyUsage, .userPresence]), [], name)
                            XCTAssertEqual(policy.accessible,
                                           isHolder && presence
                                               ? kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
                                               : kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                           name)
                            XCTAssertEqual(policy.accessGroup, isHolder ? group : nil, name)
                        }
                    }
                }
            }
        }
    }
}
