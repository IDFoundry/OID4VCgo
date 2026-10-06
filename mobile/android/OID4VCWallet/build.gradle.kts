// OID4VCWallet: the Kotlin API of OID4VCgo's mobile wallet, over the
// gomobile AAR ../../build-aar.sh builds. It links the release build
// (../../build/release/mobile.aar) unless -Poid4vc.testFramework=true,
// which links the test build (../../build/test/mobile.aar, with
// TestEnv) the instrumented tests need.
import javax.inject.Inject

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.serialization)
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
    aar.set(mobileAAR)
    jniLibs.set(layout.buildDirectory.dir("mobile/jniLibs"))
    classes.set(layout.buildDirectory.file("mobile/classes.jar"))
}

android {
    namespace = "dev.idfoundry.oid4vcwallet"
    compileSdk = 37
    defaultConfig {
        minSdk = 30
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
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
}

dependencies {
    implementation(files(unpackMobile.flatMap { it.classes }))
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(libs.junit)
}
