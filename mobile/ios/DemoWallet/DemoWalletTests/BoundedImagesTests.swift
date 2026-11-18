import UIKit
import XCTest
@testable import DemoWallet

final class BoundedImagesTests: XCTestCase {
    /// A small file can declare a huge size: refused from its header,
    /// before any pixel is decoded.
    func testRefusesSidesPastTheMaximum() {
        let bomb = Self.pngHeader(width: 20_000, height: 20_000)
        XCTAssertLessThan(bomb.count, 100)
        XCTAssertFalse(BoundedImages.accepts(bomb))
        XCTAssertNil(BoundedImages.thumbnail(bomb, pixels: 150))
        XCTAssertNil(EncodedImage(bomb))
        let base64 = bomb.base64EncodedString()
        XCTAssertNil(ClaimRows.image(.string(base64), key: "portrait"))
        XCTAssertNil(ClaimRows.image(.string("data:image/png;base64," + base64), key: "picture"))
        XCTAssertNil(Holder(claims: .object(["portrait": .string(base64)])))

        XCTAssertFalse(BoundedImages.accepts(Self.pngHeader(width: BoundedImages.maxDimension + 1, height: 1)))
        XCTAssertTrue(BoundedImages.accepts(Self.pngHeader(width: BoundedImages.maxDimension, height: 1)))
    }

    func testRefusesWhatIsntAnImage() {
        XCTAssertFalse(BoundedImages.accepts(Data("not an image".utf8)))
        XCTAssertNil(ClaimRows.image(.string(Data("none".utf8).base64EncodedString()), key: "photo"))
    }

    /// Decoded at the size shown, never at its own.
    @MainActor func testThumbnailsToTheSizeShown() throws {
        let png = UIGraphicsImageRenderer(size: CGSize(width: 300, height: 400), format: {
            let f = UIGraphicsImageRendererFormat()
            f.scale = 1
            return f
        }()).pngData { ctx in
            UIColor.gray.setFill()
            ctx.fill(CGRect(x: 0, y: 0, width: 300, height: 400))
        }
        let image = try XCTUnwrap(EncodedImage(png))
        let holder = try XCTUnwrap(Holder(claims: .object(["portrait": .string(png.base64EncodedString())])))
        XCTAssertEqual(holder.portrait?.key, image.key)

        let thumbnail = try XCTUnwrap(BoundedImages.thumbnail(image.data, pixels: 50))
        let cg = try XCTUnwrap(thumbnail.cgImage)
        XCTAssertEqual(max(cg.width, cg.height), 50)
    }

    /// A PNG declaring `width` × `height` pixels in a few dozen bytes: its
    /// IHDR, and an IDAT holding a single compressed byte (ImageIO reads
    /// no size without one).
    static func pngHeader(width: Int, height: Int) -> Data {
        var ihdr = Data(bigEndian(UInt32(width)) + bigEndian(UInt32(height)))
        ihdr.append(contentsOf: [8, 0, 0, 0, 0]) // 8-bit greyscale
        var png = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        png.append(chunk("IHDR", ihdr))
        png.append(chunk("IDAT", Data([0x78, 0x9C, 0x63, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]))) // zlib of one 0 byte
        png.append(chunk("IEND", Data()))
        return png
    }

    private static func chunk(_ type: String, _ body: Data) -> Data {
        var typed = Data(type.utf8)
        typed.append(body)
        var out = Data(bigEndian(UInt32(body.count)))
        out.append(typed)
        out.append(contentsOf: bigEndian(crc32(typed)))
        return out
    }

    private static func bigEndian(_ v: UInt32) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: v >> (24 - 8 * $0)) }
    }

    private static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            crc ^= UInt32(byte)
            for _ in 0..<8 { crc = (crc >> 1) ^ (crc & 1 == 1 ? 0xEDB8_8320 : 0) }
        }
        return ~crc
    }
}
