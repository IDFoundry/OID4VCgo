// OID4VCWallet: the Kotlin API of OID4VCgo's mobile wallet, over the
// gomobile AAR ../../build-aar.sh builds. It links the release build
// (../../build/release/mobile.aar) unless -Poid4vc.testFramework=true,
// which links the test build (../../build/test/mobile.aar, with
// TestEnv) the instrumented tests need.
import javax.inject.Inject

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.dokka)
    `maven-publish`
}

val testFramework = providers.gradleProperty("oid4vc.testFramework").map { it == "true" }.getOrElse(false)
val mobileAAR = layout.projectDirectory.file(if (testFramework) "../../build/test/mobile.aar" else "../../build/release/mobile.aar")

/**
 * Unpacks gomobile's AAR: its Java bindings (classes.jar) become a jar
 * dependency, and its native libraries (jni/) this library's own. An
 * Android library can't depend on a local AAR.
 */
abstract class UnpackMobile : DefaultTask() {
    @get:InputFile abstract val aar: RegularFileProperty
    @get:OutputDirectory abstract val jniLibs: DirectoryProperty
    @get:OutputFile abstract val classes: RegularFileProperty
    @get:Inject abstract val archives: ArchiveOperations
    @get:Inject abstract val files: FileSystemOperations

    @TaskAction
    fun unpack() {
        val tree = archives.zipTree(aar)
        files.sync {
            from(tree) { include("jni/**"); eachFile { path = path.removePrefix("jni/") }; includeEmptyDirs = false }
            into(jniLibs)
        }
        files.copy {
            from(tree) { include("classes.jar") }
            into(classes.get().asFile.parentFile)
        }
    }
}

val unpackMobile = tasks.register<UnpackMobile>("unpackMobile") {
    group = "build"
    description = "Unpacks the gomobile AAR into this library."
    aar.set(mobileAAR)
    jniLibs.set(layout.buildDirectory.dir("mobile/jniLibs"))
    classes.set(layout.buildDirectory.file("mobile/classes.jar"))
}

android {
    namespace = "dev.idfoundry.oid4vcwallet"
    compileSdk = 37
    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

androidComponents {
    onVariants { variant ->
        variant.sources.jniLibs?.addGeneratedSourceDirectory(unpackMobile, UnpackMobile::jniLibs)
    }
}

kotlin {
    jvmToolchain(17)
    explicitApi()
    // Readable by apps on Kotlin 2.2 — AGP 9's own — and later: a
    // library built with the newest compiler would otherwise need its
    // apps to have it too.
    compilerOptions {
        languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
        apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
    }
    coreLibrariesVersion = "2.2.21"
}

dependencies {
    implementation(files(unpackMobile.flatMap { it.classes }))
    implementation(libs.androidx.annotation)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(libs.junit)
}

// The API reference (./gradlew :OID4VCWallet:dokkaGenerate, into
// build/dokka/html): Module.md is its front page, and a warning fails
// it, an undocumented public declaration included. Source links point at -Poid4vc.sourceRef, the commit a release is
// built from, main by default.
dokka {
    // Lowercase: Dokka escapes capitals in its paths (-o-i-d4-v-c-wallet).
    moduleName.set("oid4vcwallet")
    dokkaSourceSets.configureEach {
        includes.from("Module.md")
        reportUndocumented.set(true)
        sourceLink {
            localDirectory.set(file("src/main/kotlin"))
            val ref = providers.gradleProperty("oid4vc.sourceRef").getOrElse("main")
            remoteUrl("https://github.com/IDFoundry/OID4VCgo/tree/$ref/mobile/android/OID4VCWallet/src/main/kotlin")
            remoteLineSuffix.set("#L")
        }
    }
    dokkaPublications.html {
        failOnWarning.set(true)
    }
}

// dev.idfoundry:oid4vcwallet, as ../package-kotlin-release.sh publishes
// it: -Poid4vc.version is the release's version (the Swift package's),
// and -Poid4vc.publishTo the Maven repository directory it's written
// into, a checkout of OID4VCgo-wallet-kotlin's.
publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "dev.idfoundry"
            artifactId = "oid4vcwallet"
            version = providers.gradleProperty("oid4vc.version").getOrElse("0.0.0-SNAPSHOT")
            afterEvaluate { from(components["release"]) }
            pom {
                name.set("OID4VCWallet")
                description.set("OID4VCgo's mobile wallet for Android: OpenID4VCI 1.0 and OpenID4VP 1.0 under HAIP 1.0, with SD-JWT VC and ISO mdoc credentials.")
                url.set("https://github.com/IDFoundry/OID4VCgo-wallet-kotlin")
                licenses {
                    license {
                        name.set("MIT")
                        url.set("https://github.com/IDFoundry/OID4VCgo/blob/main/LICENSE")
                    }
                }
                scm {
                    url.set("https://github.com/IDFoundry/OID4VCgo")
                }
            }
        }
    }
    repositories {
        providers.gradleProperty("oid4vc.publishTo").orNull?.let { dir ->
            maven {
                name = "release"
                url = uri(file(dir))
            }
        }
    }
}
