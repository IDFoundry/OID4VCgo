import ExtensionKit
import IdentityDocumentServices
import IdentityDocumentServicesUI
import SwiftUI

/// The wallet's Identity Document Provider extension: Safari, asked for
/// an mdoc over the Digital Credentials API ("org-iso-mdoc", ISO/IEC TS
/// 18013-7 Annex C), offers the wallet for the doctypes the app
/// registered, and shows this extension's sheet when the holder picks it.
@main
struct DocumentProvider: IdentityDocumentProvider {
    var body: some IdentityDocumentRequestScene {
        ISO18013MobileDocumentRequestScene { context in
            RequestView(context: context)
        }
    }

    /// The app keeps the registrations up to date whenever its
    /// credentials change; there's nothing more to do here.
    func performRegistrationUpdates() async {}
}
