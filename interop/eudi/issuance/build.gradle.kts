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

dependencies {
    implementation(libs.eudi.openid4vci)
    implementation(libs.eudi.sdjwt)
    implementation(libs.ktor.client.java)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.serialization.kotlinx.json)
    // X.509 support in openid4vci-kt (its README).
    implementation(libs.bouncycastle.pkix)
    // Reads the mdoc's IssuerSigned structure.
    implementation(libs.cbor)
    runtimeOnly(libs.slf4j.simple)
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
