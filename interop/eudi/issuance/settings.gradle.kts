// The EUDI wallet driver for interop/eudi/run-issuer.sh: the EUDI
// reference wallet library, eudi-lib-jvm-openid4vci-kt, obtaining
// credentials from cmd/conformance-issuer. See ../README.md.
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

rootProject.name = "eudi-issuance-interop"
