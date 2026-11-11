import XCTest
@testable import OID4VCWallet

/// A document provider answers only what the holder was shown before iOS
/// released the request: `Request.answers(for:readerCertificate:)`
/// refuses a released request that differs from it.
final class MdocConsentTests: XCTestCase {
    private typealias Element = MdocPresentation.Element
    private typealias Shown = MdocPresentation.Shown
    private typealias RequestChanged = MdocPresentation.RequestChanged

    private static let photoID = "org.iso.23220.photoid.1"
    private static let mDL = "org.iso.18013.5.1.mDL"
    private static let name = Element(namespace: "org.iso.23220.1", identifier: "family_name_unicode", retain: false)
    private static let birth = Element(namespace: "org.iso.23220.1", identifier: "birth_date", retain: true)
    private static let portrait = Element(namespace: "org.iso.23220.1", identifier: "portrait", retain: false)
    private static let drivingPrivileges = Element(namespace: "org.iso.18013.5.1", identifier: "driving_privileges", retain: false)
    private static let readerCert = Data([0x30, 0x82, 0x01, 0x0a])

    /// A held mdoc, as a candidate the Go side lists for one document.
    private static func credential(_ id: String, doctype: String, linkableHere: Bool = false) -> String {
        """
        {"id":"\(id)","credential_issuer":"https://issuer.example","configuration_id":"c","format":"mso_mdoc",\
        "doctype":"\(doctype)","received_at":"2026-11-11T00:00:00Z","copies":3,"copies_left":2,"refreshable":true,\
        "linkable":false,"presentable":true,"linkable_here":\(linkableHere)}
        """
    }

    private static func element(_ e: Element) -> String {
        #"{"namespace":"\#(e.namespace)","identifier":"\#(e.identifier)","retain":\#(e.retain)}"#
    }

    private static func document(_ doctype: String, _ elements: [Element], _ credentials: [String]) -> String {
        #"{"doctype":"\#(doctype)","elements":[\#(elements.map(element).joined(separator: ","))],"credentials":[\#(credentials.joined(separator: ","))]}"#
    }

    /// A released request, as `MdocPresentation.request` decodes it.
    private static func request(reader: Data? = nil, _ documents: [String]) throws -> MdocPresentation.Request {
        let cert = reader.map { #""\#($0.base64EncodedString())""# } ?? "null"
        return try decode(MdocPresentation.Request.self, """
            {"origin":"https://verifier.example","reader":"\(reader == nil ? "" : "Example Reader")",\
            "reader_certificate":\(cert),"documents":[\(documents.joined(separator: ","))]}
            """)
    }

    private static let photoIDRequest = document(photoID, [name, birth], [credential("p1", doctype: photoID), credential("p2", doctype: photoID)])
    private static let shownPhotoID = Shown(doctype: photoID, elements: [birth, name], credentialID: "p2", toldLinkable: false)

    private func assertChanged(_ reason: RequestChanged.Reason, _ body: () throws -> some Any, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            XCTAssertEqual(error as? RequestChanged, RequestChanged(reason: reason), file: file, line: line)
        }
    }

    func testAnswersWhatWasShownWhateverTheElementOrder() throws {
        let answers = try Self.request([Self.photoIDRequest]).answers(for: [Self.shownPhotoID], readerCertificate: nil)
        XCTAssertEqual(answers, [MdocPresentation.Answer(document: 0, credentialID: "p2", elements: [Self.birth, Self.name])])
    }

    func testAnswersEachShownDocumentByItsIndexInTheReleasedRequest() throws {
        let request = try Self.request([
            Self.document(Self.mDL, [Self.drivingPrivileges], [Self.credential("m1", doctype: Self.mDL)]),
            Self.photoIDRequest,
        ])
        let shownMDL = Shown(doctype: Self.mDL, elements: [Self.drivingPrivileges], credentialID: "m1", toldLinkable: false)
        let answers = try request.answers(for: [Self.shownPhotoID, shownMDL], readerCertificate: nil)
        XCTAssertEqual(answers.map(\.document), [1, 0])
    }

    func testRefusesNothingShown() throws {
        let request = try Self.request([Self.photoIDRequest])
        assertChanged(.nothingShown) { try request.answers(for: [], readerCertificate: nil) }
    }

    func testRefusesARequestThatAsksForAnotherElement() throws {
        let request = try Self.request([Self.document(Self.photoID, [Self.name, Self.birth, Self.portrait], [Self.credential("p2", doctype: Self.photoID)])])
        assertChanged(.document(doctype: Self.photoID)) { try request.answers(for: [Self.shownPhotoID], readerCertificate: nil) }
    }

    func testRefusesARequestThatAsksForFewerElements() throws {
        let request = try Self.request([Self.document(Self.photoID, [Self.name], [Self.credential("p2", doctype: Self.photoID)])])
        assertChanged(.document(doctype: Self.photoID)) { try request.answers(for: [Self.shownPhotoID], readerCertificate: nil) }
    }

    func testRefusesAnElementWhoseRetentionChanged() throws {
        // Shown as not kept, released as kept.
        let kept = Element(namespace: Self.name.namespace, identifier: Self.name.identifier, retain: true)
        let request = try Self.request([Self.document(Self.photoID, [kept, Self.birth], [Self.credential("p2", doctype: Self.photoID)])])
        assertChanged(.document(doctype: Self.photoID)) { try request.answers(for: [Self.shownPhotoID], readerCertificate: nil) }
    }

    func testRefusesARequestNoLongerAskingForAShownDocument() throws {
        let request = try Self.request([Self.document(Self.mDL, [Self.drivingPrivileges], [Self.credential("m1", doctype: Self.mDL)])])
        assertChanged(.document(doctype: Self.photoID)) { try request.answers(for: [Self.shownPhotoID], readerCertificate: nil) }
    }

    func testRefusesACredentialThatNoLongerAnswers() throws {
        let request = try Self.request([Self.document(Self.photoID, [Self.name, Self.birth], [Self.credential("p1", doctype: Self.photoID)])])
        assertChanged(.credential(doctype: Self.photoID)) { try request.answers(for: [Self.shownPhotoID], readerCertificate: nil) }
    }

    func testRefusesACredentialThatBecameLinkable() throws {
        let request = try Self.request([Self.document(Self.photoID, [Self.name, Self.birth], [Self.credential("p2", doctype: Self.photoID, linkableHere: true)])])
        assertChanged(.linkable(doctype: Self.photoID)) { try request.answers(for: [Self.shownPhotoID], readerCertificate: nil) }
    }

    func testAnswersALinkableCredentialTheHolderWasToldOf() throws {
        let request = try Self.request([Self.document(Self.photoID, [Self.name, Self.birth], [Self.credential("p2", doctype: Self.photoID, linkableHere: true)])])
        let told = Shown(doctype: Self.photoID, elements: [Self.name, Self.birth], credentialID: "p2", toldLinkable: true)
        XCTAssertEqual(try request.answers(for: [told], readerCertificate: nil).count, 1)
    }

    func testAnswersTheReaderShown() throws {
        let request = try Self.request(reader: Self.readerCert, [Self.photoIDRequest])
        XCTAssertEqual(try request.answers(for: [Self.shownPhotoID], readerCertificate: Self.readerCert).count, 1)
    }

    func testRefusesAnotherReadersCertificate() throws {
        let request = try Self.request(reader: Data([0x30, 0x82, 0x01, 0x0b]), [Self.photoIDRequest])
        assertChanged(.reader) { try request.answers(for: [Self.shownPhotoID], readerCertificate: Self.readerCert) }
    }

    func testRefusesAnUnsignedRequestWhenAReaderWasShown() throws {
        let request = try Self.request([Self.photoIDRequest])
        assertChanged(.reader) { try request.answers(for: [Self.shownPhotoID], readerCertificate: Self.readerCert) }
    }

    func testAnyReaderWhenOnlyTheOriginWasShown() throws {
        let request = try Self.request(reader: Self.readerCert, [Self.photoIDRequest])
        XCTAssertEqual(try request.answers(for: [Self.shownPhotoID], readerCertificate: nil).count, 1)
    }

    func testOneChangedDocumentRefusesTheWholeResponse() throws {
        let request = try Self.request([
            Self.document(Self.mDL, [Self.drivingPrivileges, Self.portrait], [Self.credential("m1", doctype: Self.mDL)]),
            Self.photoIDRequest,
        ])
        let shownMDL = Shown(doctype: Self.mDL, elements: [Self.drivingPrivileges], credentialID: "m1", toldLinkable: false)
        assertChanged(.document(doctype: Self.mDL)) { try request.answers(for: [Self.shownPhotoID, shownMDL], readerCertificate: nil) }
    }
}
