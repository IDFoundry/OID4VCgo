import SwiftUI

@main
struct DemoWalletApp: App {
    @State private var model = WalletModel()
    @State private var inPerson = InPersonModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .environment(inPerson)
                .onOpenURL { model.openFromOutside($0) }
                // iOS snapshots the window for the app switcher as the
                // scene leaves the foreground: cover claims and portraits
                // first.
                .overlay { if scenePhase != .active { PrivacyCover() } }
                // The reader's revocation lists at launch (the wallet
                // fetches its own as it starts).
                .task { await inPerson.refreshReaderCRLs(model) }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active {
                Task {
                    await model.becameActive()
                    if inPerson.readerCRLsDue(model) { await inPerson.refreshReaderCRLs(model) }
                }
            }
        }
    }
}

/// What the app switcher's snapshot shows instead of the wallet's screens.
struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.background)
            Image(systemName: "wallet.pass")
                .font(.system(size: 64))
                .foregroundStyle(.secondary)
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}
