// Every configuration's versions are locked (gradle.lockfile, the
// buildscript's in buildscript-gradle.lockfile). After changing a
// dependency: ./gradlew resolveAndLockAll --write-locks
buildscript {
    configurations.classpath {
        resolutionStrategy.activateDependencyLocking()
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
