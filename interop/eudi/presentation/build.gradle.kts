// Every configuration's versions are locked (gradle.lockfile, the
// plugins' in buildscript-gradle.lockfile), and each artifact's
// checksum recorded (gradle/verification-metadata.xml). After changing
// a dependency, from an empty Gradle cache:
//   ./gradlew --write-verification-metadata sha256 --write-locks dependencies installDist
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

buildscript {
    configurations.classpath {
        resolutionStrategy.activateDependencyLocking()
    }
}

plugins {
    kotlin("jvm") version "2.4.20"
    application
}

// Every version is exact, and the lockfiles pin the transitive ones.
// Move the EUDI libraries and Multipaz only after reading their
// releases' changes.
dependencies {
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-openid4vp-kt:0.17.0")
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-sdjwt-kt:0.21.0")
    implementation("org.multipaz:multipaz-jvm:0.102.0") {
        // Android Key Attestation parsing, published on Google's
        // repository alone: nothing this driver calls uses it.
        exclude(group = "com.android.keyattestation")
    }
    implementation("io.ktor:ktor-client-java:3.6.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    // Bouncy Castle at the version mobile/android pins, past the 1.83
    // the EUDI libraries ask for.
    listOf("bcprov", "bcpkix", "bcutil").forEach { implementation("org.bouncycastle:$it-jdk18on:1.85") }
}

dependencyLocking {
    lockAllConfigurations()
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_21)
        allWarningsAsErrors.set(true)
    }
}

application {
    mainClass.set("dev.idfoundry.interop.eudi.MainKt")
}
