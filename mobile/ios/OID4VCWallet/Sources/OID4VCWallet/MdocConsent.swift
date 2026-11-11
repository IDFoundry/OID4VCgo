import Foundation

extension MdocPresentation {
    /// What the holder agreed to share of one document, from what iOS
    /// showed before it released the request: a document provider
    /// records it on the consent screen and checks the released request
    /// against it with ``Request/answers(for:readerCertificate:)``.
    public struct Shown: Sendable, Hashable {
        /// The document's type.
        public let doctype: String
        /// The elements the holder was shown, which the answer discloses.
        public let elements: [Element]
        /// The held mdoc the holder chose.
        public let credentialID: String
        /// Whether the holder was told presenting it would be linkable
        /// (``CredentialSummary/linkableHere``).
        public let toldLinkable: Bool

        /// What the holder agreed to for one document.
        public init(doctype: String, elements: [Element], credentialID: String, toldLinkable: Bool) {
            self.doctype = doctype
            self.elements = elements
            self.credentialID = credentialID
            self.toldLinkable = toldLinkable
        }
    }

    /// The released request isn't what the holder was shown: nothing was
    /// answered.
    public struct RequestChanged: Error, Sendable, Equatable, CustomStringConvertible {
        /// How it differs.
        public enum Reason: Sendable, Equatable {
            /// Nothing was agreed to.
            case nothingShown
            /// The holder was shown a reader, and the request isn't
            /// signed by that reader's certificate.
            case reader
            /// The request no longer asks for `doctype`, or asks for
            /// other elements of it.
            case document(doctype: String)
            /// The credential chosen for `doctype` no longer answers it.
            case credential(doctype: String)
            /// Presenting the credential chosen for `doctype` would now
            /// be linkable, and the holder wasn't told.
            case linkable(doctype: String)
        }

        /// How it differs.
        public let reason: Reason

        public var description: String {
            switch reason {
            case .nothingShown: return "nothing was agreed to"
            case .reader: return "the request isn't signed by the reader shown"
            case let .document(doctype): return "the request for \(doctype) changed after it was shown"
            case let .credential(doctype): return "the credential chosen for \(doctype) no longer answers the request"
            case let .linkable(doctype): return "presenting the credential chosen for \(doctype) would now be linkable"
            }
        }
    }

    /// Answers the request with what the holder was shown
    /// (``Request/answers(for:readerCertificate:)``): `respond(answers:)`
    /// once the check passes.
    public func respond(shown: [Shown], readerCertificate: Data?) async throws -> Response {
        try await respond(answers: request.answers(for: shown, readerCertificate: readerCertificate))
    }
}

extension MdocPresentation.Request {
    /// The answers to this request that disclose exactly what the holder
    /// was shown, document by document; throws
    /// ``MdocPresentation/RequestChanged`` when the request differs from
    /// it. `readerCertificate` is the certificate of the reader the
    /// consent screen named, nil when it showed only the origin: then any
    /// reader, or none, may have signed the request.
    ///
    /// Each shown document must still be requested with the same set of
    /// elements, its chosen credential must still answer it, and that
    /// credential mustn't have become linkable here unless the holder was
    /// told.
    public func answers(for shown: [MdocPresentation.Shown], readerCertificate: Data?) throws -> [MdocPresentation.Answer] {
        guard !shown.isEmpty else { throw MdocPresentation.RequestChanged(reason: .nothingShown) }
        // The certificate, not just its name: two can share one.
        if let readerCertificate, self.readerCertificate != readerCertificate {
            throw MdocPresentation.RequestChanged(reason: .reader)
        }
        return try shown.map { s in
            guard let index = documents.firstIndex(where: { $0.doctype == s.doctype }),
                  Set(documents[index].elements) == Set(s.elements) else {
                throw MdocPresentation.RequestChanged(reason: .document(doctype: s.doctype))
            }
            guard let credential = documents[index].credentials.first(where: { $0.id == s.credentialID }) else {
                throw MdocPresentation.RequestChanged(reason: .credential(doctype: s.doctype))
            }
            if credential.linkableHere == true, !s.toldLinkable {
                throw MdocPresentation.RequestChanged(reason: .linkable(doctype: s.doctype))
            }
            return MdocPresentation.Answer(document: index, credentialID: s.credentialID, elements: s.elements)
        }
    }
}
