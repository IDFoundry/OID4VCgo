// The demo wallet app: OID4VCWallet's counterpart of mobile/ios/DemoWallet.
// It links the release Go library unless -Poid4vc.testFramework=true.
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "dev.idfoundry.oid4vcgo.demowallet"
    compileSdk = 37
    defaultConfig {
        applicationId = "dev.idfoundry.oid4vcgo.demowallet"
        minSdk = 30
        targetSdk = 37
        versionCode = 1
        versionName = "0.1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildFeatures {
        compose = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":OID4VCWallet"))
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.browser)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.coil.compose)
    implementation(libs.coil.network)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.mlkit.barcode.scanning)
    implementation(libs.zxing.core)
    // The Digital Credentials API: Credential Manager's registry, and
    // its matchers for OpenID4VP's mdoc and SD-JWT VC entries.
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.credentials.registry.provider)
    implementation(libs.androidx.credentials.registry.play.services)
    implementation(libs.androidx.credentials.registry.openid)
    implementation(libs.androidx.credentials.registry.mdoc)
    implementation(libs.androidx.credentials.registry.sdjwtvc)
}
