import CryptoKit
import ImageIO
import SwiftUI
import UIKit

/// Images an issuer chose — a credential's logo, a holder's portrait —
/// decoded as hostile: a small file can declare a size that decodes to
/// hundreds of megabytes. Each is refused past `maxDimension` pixels a
/// side, read from its header before any pixel is decoded, and
/// thumbnailed by ImageIO, which never decodes the whole image at full
/// size, to about the size it's shown.
enum BoundedImages {
    /// The widest or tallest image decoded, in pixels.
    static let maxDimension = 4096

    /// Whether `data`'s header names an image `thumbnail` would decode.
    /// Reads no pixels.
    static func accepts(_ data: Data) -> Bool {
        source(data) != nil
    }

    /// `data` decoded at most `pixels` a side: its size read first,
    /// refused past `maxDimension`, then thumbnailed. Call it off the
    /// main actor.
    static func thumbnail(_ data: Data, pixels: Int) -> UIImage? {
        guard let source = source(data) else { return nil }
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceShouldCacheImmediately: true,
            kCGImageSourceThumbnailMaxPixelSize: max(pixels, 1),
        ]
        guard let image = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary) else { return nil }
        return UIImage(cgImage: image)
    }

    /// An image source for `data` if its header gives a size within
    /// `maxDimension`.
    private static func source(_ data: Data) -> CGImageSource? {
        guard let source = CGImageSourceCreateWithData(data as CFData, [kCGImageSourceShouldCache: false] as CFDictionary),
              let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
              let width = properties[kCGImagePropertyPixelWidth] as? Int,
              let height = properties[kCGImagePropertyPixelHeight] as? Int,
              (1...maxDimension).contains(width), (1...maxDimension).contains(height) else { return nil }
        return source
    }
}

/// An image claim's bytes — an mdoc's portrait, an SD-JWT VC's picture —
/// whose header `BoundedImages` accepted. Its pixels are decoded only by
/// `ClaimImage`, off the main actor, at the size shown.
struct EncodedImage: Sendable {
    let data: Data
    /// Its SHA-256: what its decoded thumbnails are cached by.
    let key: String

    /// `data` as an image claim, if `BoundedImages` accepts its header.
    init?(_ data: Data) {
        guard BoundedImages.accepts(data) else { return nil }
        self.data = data
        key = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

/// Claim images decoded at the sizes they're shown, kept in memory: the
/// home screen shows each holder's portrait whenever it's drawn, and
/// decodes it once.
@MainActor
enum ClaimImages {
    private static let cache: NSCache<NSString, UIImage> = {
        let cache = NSCache<NSString, UIImage>()
        cache.countLimit = 64
        return cache
    }()

    static func cached(_ id: String) -> UIImage? {
        cache.object(forKey: id as NSString)
    }

    /// `image` at most `pixels` a side, decoded off the main actor.
    static func image(_ image: EncodedImage, pixels: Int, id: String) async -> UIImage? {
        if let cached = cached(id) { return cached }
        let data = image.data
        let decoded = await Task.detached(priority: .utility) { BoundedImages.thumbnail(data, pixels: pixels) }.value
        if let decoded { cache.setObject(decoded, forKey: id as NSString) }
        return decoded
    }
}

/// An image claim in a `width` × `height` frame, filled or fitted:
/// decoded off the main actor at that size, its space kept empty until
/// it is, or if it can't be.
struct ClaimImage: View {
    let image: EncodedImage
    let width: CGFloat
    let height: CGFloat
    var fill = false
    @Environment(\.displayScale) private var scale
    @State private var loaded: (id: String, image: UIImage?)?

    var body: some View {
        let pixels = Int((max(width, height) * scale).rounded(.up))
        let id = "\(image.key)@\(pixels)"
        if let shown = loaded.flatMap({ $0.id == id ? $0.image : nil }) ?? ClaimImages.cached(id) {
            if fill {
                Image(uiImage: shown).resizable().scaledToFill().frame(width: width, height: height)
            } else {
                Image(uiImage: shown).resizable().scaledToFit().frame(maxWidth: width, maxHeight: height)
            }
        } else {
            Color.clear.frame(width: fill ? width : 0, height: fill ? height : 0)
                .task(id: id) {
                    loaded = (id, await ClaimImages.image(image, pixels: pixels, id: id))
                }
        }
    }
}
