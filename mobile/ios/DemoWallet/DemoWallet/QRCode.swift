import CoreImage

/// Reads the QR codes in an image: a photo or screenshot of a Credential
/// Offer or presentation request. Core Image's detector, which runs
/// everywhere; Vision's barcode detector can't run on an Intel Mac's
/// Simulator.
enum QRCode {
    /// The payloads of the QR codes in `image`, in no particular order.
    static func payloads(in image: CGImage) throws -> [String] {
        guard let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil,
                                        options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]) else {
            throw QRCodeError()
        }
        return detector.features(in: CIImage(cgImage: image)).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
    }

    /// The first payload that's a link the wallet opens.
    static func walletLink(in image: CGImage) throws -> URL? {
        try payloads(in: image).lazy.compactMap(URL.init(string:)).first(where: isWalletLink)
    }

    static func isWalletLink(_ url: URL) -> Bool {
        url.scheme == "openid-credential-offer" || url.scheme == "openid4vp"
    }

    /// A QR code holding `text`, for tests.
    static func image(of text: String) -> CGImage? {
        let filter = CIFilter(name: "CIQRCodeGenerator", parameters: ["inputMessage": Data(text.utf8), "inputCorrectionLevel": "M"])
        guard let output = filter?.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)) else { return nil }
        return CIContext().createCGImage(output, from: output.extent)
    }
}

struct QRCodeError: LocalizedError {
    var errorDescription: String? { "QR code detection isn't available" }
}
