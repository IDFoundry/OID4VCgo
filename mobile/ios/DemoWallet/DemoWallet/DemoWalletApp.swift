import SwiftUI

@main
struct DemoWalletApp: App {
    @State private var model = WalletModel()
    @State private var inPerson = InPersonModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(model)
                .environment(inPerson)
                .onOpenURL { model.openFromOutside($0) }
        }
    }
}
