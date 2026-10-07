import PhotosUI
import SwiftUI
import VisionKit

/// Scans a Credential Offer or presentation request QR code — or, with
/// `accept`, another kind — live with the camera where the device can, or
/// from an image in Photos.
struct ScanView: View {
    @Environment(\.dismiss) private var dismiss
    var accept: (URL) -> Bool = QRCode.isWalletLink
    var what = "credential offer or presentation request"
    let open: (URL) -> Void
    @State private var photo: PhotosPickerItem?
    @State private var message: String?

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                    LiveScanner(accept: accept) { url in
                        dismiss()
                        open(url)
                    }
                    .clipShape(RoundedRectangle(cornerRadius: 16))
                    .accessibilityIdentifier("camera")
                } else {
                    ContentUnavailableView("No camera scanning here", systemImage: "camera",
                                           description: Text("Choose a photo or screenshot of the QR code instead."))
                }
                PhotosPicker("Choose a QR code image", selection: $photo, matching: .images)
                    .accessibilityIdentifier("choose-image")
                if let message {
                    Text(message).foregroundStyle(.red).accessibilityIdentifier("scan-message")
                }
            }
            .padding()
            .navigationTitle("Scan")
            .toolbar { Button("Cancel") { dismiss() } }
            .onChange(of: photo) { _, item in Task { await read(item) } }
        }
    }

    private func read(_ item: PhotosPickerItem?) async {
        guard let item else { return }
        guard let data = try? await item.loadTransferable(type: Data.self),
              let image = UIImage(data: data)?.cgImage else {
            message = "That image couldn't be read."
            return
        }
        if let url = try? QRCode.payloads(in: image).lazy.compactMap(URL.init(string:)).first(where: accept) {
            dismiss()
            open(url)
        } else {
            message = "No \(what) QR code in that image."
        }
    }
}

/// VisionKit's live QR scanner, reporting the first wallet link it sees.
private struct LiveScanner: UIViewControllerRepresentable {
    let accept: (URL) -> Bool
    let found: (URL) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])],
                                                qualityLevel: .balanced, isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        try? scanner.startScanning()
        return scanner
    }

    func updateUIViewController(_: DataScannerViewController, context _: Context) {
        // Nothing to update: the scanner is configured once, in
        // makeUIViewController, and reports through its coordinator.
    }

    func makeCoordinator() -> Coordinator { Coordinator(accept: accept, found: found) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let accept: (URL) -> Bool
        let found: (URL) -> Void
        private var done = false

        init(accept: @escaping (URL) -> Bool, found: @escaping (URL) -> Void) {
            self.accept = accept
            self.found = found
        }

        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem], allItems _: [RecognizedItem]) {
            guard !done else { return }
            for case .barcode(let code) in items {
                if let text = code.payloadStringValue, let url = URL(string: text), accept(url) {
                    done = true
                    scanner.stopScanning()
                    found(url)
                    return
                }
            }
        }
    }
}
