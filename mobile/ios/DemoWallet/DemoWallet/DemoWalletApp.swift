import SwiftUI

@main
struct DemoWalletApp: App {
    @State private var model = WalletModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(model)
                .onOpenURL { model.openFromOutside($0) }
        }
        // The document provider extension presents from its own process,
        // using copies in the shared store: list them again on return.
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { Task { await model.refresh() } }
        }
    }
}
