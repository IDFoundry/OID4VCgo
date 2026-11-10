// The Multipaz driver for interop/multipaz/run.sh: Multipaz's mdoc
// reader, holder and Annex C verifier and wallet, against OID4VCgo's
// (../scripts/peer). See ../README.md.
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

rootProject.name = "multipaz-interop"
