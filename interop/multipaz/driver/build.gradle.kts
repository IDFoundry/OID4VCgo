// Every version is pinned exactly (gradle/libs.versions.toml), every
// configuration's resolved versions are locked (gradle.lockfile, the
// buildscript's in buildscript-gradle.lockfile), and every artifact's
// checksum is verified (gradle/verification-metadata.xml). After
// changing a dependency, with an empty Gradle cache (GRADLE_USER_HOME)
// so every artifact is fetched and recorded:
//   ./gradlew --write-verification-metadata sha256 --write-locks resolveAndLockAll installDist
buildscript {
    configurations.classpath {
        resolutionStrategy.activateDependencyLocking()
    }
}

plugins {
    alias(libs.plugins.kotlin.jvm)
    application
}

dependencyLocking {
    lockAllConfigurations()
}

// Multipaz's JVM library also depends on Google's Android Key
// Attestation verifier and androidx's annotations, which are on
// Google's Maven repository, not Maven Central. The driver verifies no
// Android key attestation, so they're left out rather than another
// repository let in.
configurations.configureEach {
    exclude(group = "com.android.keyattestation")
    exclude(group = "androidx.annotation")
}

dependencies {
    implementation(libs.multipaz)
    implementation(libs.multipaz.doctypes)
    implementation(libs.ktor.client.java)
    runtimeOnly(libs.slf4j.simple)
}

// Multipaz's JVM library targets Java 21.
kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

application {
    mainClass.set("oid4vcgo.interop.multipaz.MainKt")
}

tasks.register("resolveAndLockAll") {
    group = "dependency locking"
    description = "Resolves every configuration, for --write-locks."
    notCompatibleWithConfigurationCache("resolves configurations at execution time")
    doFirst {
        require(gradle.startParameter.isWriteDependencyLocks) { "run with --write-locks" }
    }
    doLast {
        configurations.filter { it.isCanBeResolved }.forEach { it.resolve() }
    }
}
