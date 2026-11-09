// Every configuration's versions are locked (gradle.lockfile, the
// buildscript's in buildscript-gradle.lockfile). After changing a
// dependency: ./gradlew resolveAndLockAll --write-locks
buildscript {
    configurations.classpath {
        resolutionStrategy.activateDependencyLocking()
    }
    // The Gradle plugins' own dependencies, raised past versions with
    // published vulnerabilities (OSV, via the OpenSSF Scorecard). They
    // run only in the build, never in the library or the apps; remove a
    // line once the plugins require that version or later themselves.
    dependencies {
        constraints {
            listOf(
                "com.fasterxml.jackson.core:jackson-annotations",
                "com.fasterxml.jackson.core:jackson-core",
                "com.fasterxml.jackson.core:jackson-databind",
                "com.fasterxml.jackson.dataformat:jackson-dataformat-xml",
                "com.fasterxml.jackson.module:jackson-module-kotlin",
            ).forEach { classpath("$it:2.18.11") }
            listOf("bcprov", "bcpkix", "bcutil").forEach { classpath("org.bouncycastle:$it-jdk18on:1.85") }
            classpath("org.bitbucket.b_c:jose4j:0.9.6")
            classpath("org.jdom:jdom2:2.0.6.1")
            classpath("org.apache.commons:commons-lang3:3.18.0")
            classpath("com.google.guava:guava:33.7.2-jre")
        }
    }
}

plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.test) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.dokka) apply false
}

allprojects {
    dependencyLocking {
        lockAllConfigurations()
    }

    tasks.register("resolveAndLockAll") {
        group = "dependency locking"
        description = "Resolves every configuration, for --write-locks."
        notCompatibleWithConfigurationCache("resolves configurations at execution")
        doFirst {
            require(gradle.startParameter.isWriteDependencyLocks) { "run with --write-locks" }
        }
        doLast {
            // The classpaths: what builds and ships. Android's other
            // resolvable configurations need attributes to resolve.
            configurations.filter { it.isCanBeResolved && it.name.endsWith("Classpath") }.forEach { it.incoming.resolutionResult.root }
        }
    }
}
