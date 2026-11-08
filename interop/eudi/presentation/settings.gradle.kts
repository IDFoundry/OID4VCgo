// The wallet side of interop/eudi/run-wallet.sh: a command-line driver
// that answers OID4VCgo's cmd/conformance-verifier with the EUDI
// reference libraries (eudi-lib-jvm-openid4vp-kt, eudi-lib-jvm-sdjwt-kt)
// and Multipaz. See ../README.md.
pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
    }
}

rootProject.name = "eudi-presentation-driver"
