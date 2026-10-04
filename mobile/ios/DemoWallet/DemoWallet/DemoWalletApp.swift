import SwiftUI

@main
struct DemoWalletApp: App {
    @State private var model = WalletModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(model)
                .onOpenURL { model.openFromOutside($0) }
        }
    }
}
