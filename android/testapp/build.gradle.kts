import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// Debug-only companion app used to exercise autofill end to end (native login form + WebView login page).
plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "org.friendlypass.testapp"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.friendlypass.testapp"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "0.1"
    }

    buildTypes {
        debug {
            isDebuggable = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

dependencies {
    // WebViewAssetLoader: serves assets/login.html from https://appassets.androidplatform.net/.
    implementation(libs.androidx.webkit)
}
