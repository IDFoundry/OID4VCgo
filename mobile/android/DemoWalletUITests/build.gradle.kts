// The demo wallet's UI tests, as the iOS demo's XCUITests: UiAutomator
// driving the installed app from outside it (a self-instrumenting test
// app), so a test can quit and relaunch it and answer the system's own
// screen-lock prompt. run-ui-tests.sh (in ../DemoWallet) runs them
// against mobile/cmd/testservices.
plugins {
    alias(libs.plugins.android.test)
}

android {
    namespace = "dev.idfoundry.oid4vcgo.demowallet.uitests"
    compileSdk = 37
    targetProjectPath = ":DemoWallet"
    defaultConfig {
        minSdk = 30
        targetSdk = 37
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    experimentalProperties["android.experimental.self-instrumenting"] = true
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(libs.androidx.test.runner)
    implementation(libs.androidx.test.junit)
    implementation(libs.androidx.test.uiautomator)
    implementation(libs.junit)
    implementation(libs.kotlinx.serialization.json)
}
