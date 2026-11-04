import Foundation
import XCTest
@testable import OID4VCWallet

final class CRLRefreshTests: XCTestCase {
    /// The Go side's RefreshCRLs JSON decodes, its times as Dates.
    func testResultDecodes() throws {
        let json = #"{"abi":14,"results":[{"url":"http://ca.example/a.crl","outcome":"updated"},{"url":"http://ca.example/b.crl","outcome":"failed","error":"[network] network error: refused"}],"crls":"-----BEGIN X509 CRL-----\n","next_refresh":"2026-11-04T10:00:00Z"}"#
        let r = try CRLRefreshResult.from(json: json)
        XCTAssertEqual(r.results.map(\.outcome), [.updated, .failed])
        XCTAssertNil(r.results[0].error)
        XCTAssertEqual(r.results[1].error, "[network] network error: refused")
        XCTAssertTrue(r.anyFailed)
        XCTAssertEqual(r.crls, "-----BEGIN X509 CRL-----\n")
        XCTAssertEqual(r.nextRefresh, ISO8601DateFormatter().date(from: "2026-11-04T10:00:00Z"))
    }

    /// The distribution points reach the Go side under its keys.
    func testConfigurationKeys() throws {
        let point = CRLDistributionPoint(url: "http://ca.example/ca.crl", issuer: "PEM")
        let config = WalletConfiguration(crlDistributionPoints: [point], crlDistributionPointsFromRoots: true, crlRequireHTTPS: true)
        let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(config)) as? [String: Any]
        XCTAssertEqual((object?["crl_distribution_points"] as? [[String: String]])?.first, ["url": "http://ca.example/ca.crl", "issuer": "PEM"])
        XCTAssertEqual(object?["crl_distribution_points_from_roots"] as? Bool, true)
        XCTAssertEqual(object?["crl_require_https"] as? Bool, true)
        let decoded = try JSONDecoder().decode(WalletConfiguration.self, from: JSONEncoder().encode(config))
        XCTAssertEqual(decoded.crlDistributionPoints, [point])
    }

    /// `developmentRoots` reaches the Go side as `development_roots`, for
    /// a wallet and a reader alike, and a reader refuses it outside
    /// development.
    func testDevelopmentRoots() throws {
        let wallet = try JSONSerialization.jsonObject(with: JSONEncoder().encode(
            WalletConfiguration(development: true, developmentRoots: "PEM"))) as? [String: Any]
        XCTAssertEqual(wallet?["development_roots"] as? String, "PEM")
        let decoded = try JSONDecoder().decode(WalletConfiguration.self, from: Data(#"{"development":true,"development_roots":"PEM"}"#.utf8))
        XCTAssertEqual(decoded.developmentRoots, "PEM")

        let readerConfig = ProximityReaderConfiguration(issuerRoots: "", development: true, developmentRoots: "PEM")
        let reader = try JSONSerialization.jsonObject(with: JSONEncoder().encode(readerConfig)) as? [String: Any]
        XCTAssertEqual(reader?["development_roots"] as? String, "PEM")
        XCTAssertEqual(try JSONDecoder().decode(ProximityReaderConfiguration.self, from: JSONEncoder().encode(readerConfig)).developmentRoots, "PEM")

        let issuerRoots = try TestEnv().configuration.issuerRoots
        do {
            _ = try ProximityReader(configuration: ProximityReaderConfiguration(
                issuerRoots: issuerRoots, revocation: [.issuer, .status], anyIssuerForAnyType: true, statusCheck: .check,
                developmentRoots: issuerRoots), keys: nil)
            XCTFail("a production reader took development_roots")
        } catch let error as WalletError {
            XCTAssertEqual(error.code, .invalidInput)
        }
    }

    /// With no distribution points, a refresh is `invalidInput`
    /// `not_configured`; outside development, a point on a loopback
    /// address fails as `network`, and the result still comes back.
    func testReaderRefresh() async throws {
        let issuerRoots = try TestEnv().configuration.issuerRoots
        let none = try ProximityReader(configuration: ProximityReaderConfiguration(issuerRoots: issuerRoots, development: true), keys: nil)
        do {
            _ = try await none.refreshCRLs()
            XCTFail("a refresh with no distribution points ran")
        } catch let error as WalletError {
            XCTAssertEqual(error.code, .invalidInput)
            XCTAssertEqual(error.protocolError, "not_configured")
        }

        let reader = try ProximityReader(configuration: ProximityReaderConfiguration(
            issuerRoots: issuerRoots, revocation: [.issuer, .status], anyIssuerForAnyType: true, statusCheck: .check,
            crlDistributionPoints: [CRLDistributionPoint(url: "http://127.0.0.1:9/ca.crl", issuer: issuerRoots)]), keys: nil)
        let r = try await reader.refreshCRLs()
        XCTAssertEqual(r.results.map(\.outcome), [.failed])
        XCTAssertTrue(r.results[0].error?.hasPrefix("[network]") ?? false, r.results[0].error ?? "")
        XCTAssertEqual(r.crls, "")
        XCTAssertGreaterThan(r.nextRefresh, Date())
    }
}
