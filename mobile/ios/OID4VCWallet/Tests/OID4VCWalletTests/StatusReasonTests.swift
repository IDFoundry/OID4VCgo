import Foundation
import XCTest
@testable import OID4VCWallet

final class StatusReasonTests: XCTestCase {
    /// A status's reason decodes; one this version doesn't know is kept
    /// as it is, and a valid status, or one recorded before reasons were
    /// kept, has none.
    func testCredentialStatusReason() throws {
        let reasons: [(String, CredentialStatus.Reason)] = [
            ("status_list", .statusList), ("identifier_list", .identifierList),
            ("issuer_certificate_revoked", .issuerCertificateRevoked), ("issuer_untrusted", .issuerUntrusted),
            ("no_current_crl", .noCurrentCRL), ("unrecognized_status", .unrecognizedStatus),
            ("something_new", .other("something_new")),
        ]
        for (raw, want) in reasons {
            let s = try decode(CredentialStatus.self, #"{"value": "invalid", "reason": "\#(raw)", "checked_at": "2026-11-04T00:00:00Z"}"#)
            XCTAssertEqual(s.reason, want, raw)
        }
        let valid = try decode(CredentialStatus.self, #"{"value": "valid", "checked_at": "2026-11-04T00:00:00Z"}"#)
        XCTAssertEqual(valid.value, .valid)
        XCTAssertNil(valid.reason)
    }

    /// An error caused by a revocation check says which, whatever its code.
    func testRevocationDetails() {
        let revoked = WalletError(text: "[protocol:certificate_revoked] issuer certificate: revoked")
        XCTAssertEqual(revoked.code, .protocolError)
        XCTAssertTrue(revoked.isCertificateRevoked)
        XCTAssertFalse(revoked.isNoCurrentCRL)
        let stale = WalletError(text: "[untrusted_verifier:no_current_crl] no current CRL")
        XCTAssertEqual(stale.code, .untrustedVerifier)
        XCTAssertTrue(stale.isNoCurrentCRL)
        XCTAssertFalse(stale.isCertificateRevoked)
        XCTAssertFalse(WalletError(text: "[protocol] something else").isCertificateRevoked)
    }
}
