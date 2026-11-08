// Every version is pinned exactly, every configuration's resolved
// versions are locked (gradle.lockfile, the buildscript's in
// buildscript-gradle.lockfile), and every artifact's checksum is
// verified (gradle/verification-metadata.xml). After changing a
// dependency:
//   ./gradlew --write-verification-metadata sha256 --write-locks resolveAndLockAll installDist
buildscript {
    configurations.classpath {
        resolutionStrategy.activateDependencyLocking()
    }
}

plugins {
    kotlin("jvm") version "2.4.20"
    application
}

dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    // The wallet under test, and EUDI's SD-JWT VC verifier.
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-openid4vci-kt:0.16.0")
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-sdjwt-kt:0.21.0")
    implementation("io.ktor:ktor-client-java:3.6.0")
    implementation("io.ktor:ktor-client-content-negotiation:3.6.0")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.6.0")
    // X.509 support in openid4vci-kt (its README).
    implementation("org.bouncycastle:bcpkix-jdk18on:1.83")
    // Reads the mdoc's IssuerSigned structure.
    implementation("co.nstant.in:cbor:0.9")
    runtimeOnly("org.slf4j:slf4j-simple:2.0.17")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

application {
    mainClass.set("oid4vcgo.interop.eudi.MainKt")
}

// Resolves every resolvable configuration, so --write-locks locks them
// all.
tasks.register("resolveAndLockAll") {
    notCompatibleWithConfigurationCache("resolves configurations at execution time")
    doFirst {
        require(gradle.startParameter.isWriteDependencyLocks) { "run with --write-locks" }
    }
    doLast {
        configurations.filter { it.isCanBeResolved }.forEach { it.resolve() }
    }
}
