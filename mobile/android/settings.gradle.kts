// The Android side of OID4VCgo's mobile wallet SDK: the Kotlin library
// wrapping the gomobile AAR (../build-aar.sh), and the demo wallet app on
// it. See ../../MOBILE.md.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "OID4VCgo-android"
include(":OID4VCWallet")
include(":DemoWallet")
