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
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { Task { await model.becameActive() } }
        }
    }
}
