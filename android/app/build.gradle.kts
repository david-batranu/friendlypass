import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// ---------------------------------------------------------------------------
// App version
//
// `appVersionName` is the single source of truth for the Android version; the
// release workflow checks it against the git tag, the Cargo workspace version
// and the extension manifests. `appVersionCode` is derived from it so it grows
// monotonically with every release (0.1.0 -> 100) instead of being a
// hand-maintained constant.
// ---------------------------------------------------------------------------

val appVersionName = "0.1.1"

val appVersionCode: Int = run {
    val parts = appVersionName.split('.')
    require(parts.size == 3 && parts.all { it.toIntOrNull() != null }) {
        "appVersionName must be MAJOR.MINOR.PATCH, got '$appVersionName'"
    }
    parts[0].toInt() * 10_000 + parts[1].toInt() * 100 + parts[2].toInt()
}

// ---------------------------------------------------------------------------
// Release signing
//
// Signing is opt-in through environment variables so local builds and dry runs
// keep producing an unsigned APK exactly as before:
//
//   FP_ANDROID_KEYSTORE          path to the .jks/.p12 keystore
//   FP_ANDROID_KEYSTORE_PASSWORD
//   FP_ANDROID_KEY_ALIAS
//   FP_ANDROID_KEY_PASSWORD
//
// CI decodes the keystore from repository secrets into a temporary file. Never
// commit a keystore or a password.
// ---------------------------------------------------------------------------

val releaseKeystorePath = System.getenv("FP_ANDROID_KEYSTORE")?.takeIf { it.isNotBlank() }

// AGP needs the right KeyStore implementation: PKCS#12 (JDK's default) or the
// legacy JKS format. The workflow keeps the decoded file's real extension.
val releaseKeystoreType = when {
    releaseKeystorePath == null -> null
    releaseKeystorePath.endsWith(".p12", ignoreCase = true) ||
        releaseKeystorePath.endsWith(".pfx", ignoreCase = true) ||
        releaseKeystorePath.endsWith(".pkcs12", ignoreCase = true) -> "PKCS12"
    else -> "JKS"
}

// ---------------------------------------------------------------------------
// Rust / UniFFI wiring
//
// The workspace Cargo.toml is one level above this Gradle project. `cargo ndk`
// cross-compiles the UniFFI cdylib for the two ABIs the contract requires;
// `uniffi-bindgen` then emits the Kotlin bindings from that .so. Both tasks
// read their tool locations from local.properties so the build is not tied to
// one machine layout:
//
//   sdk.dir=...            (Android SDK, already used by AGP)
//   rust.cargoDir=...      directory containing `cargo` and `cargo-ndk`
//
// RUSTUP_BIN_DIR (environment variable, optional) names a directory holding the
// rustup-managed `cargo`. Without it, PATH and ~/.cargo/bin are searched. The Rust
// source tree is declared as task input, so an unchanged checkout skips both
// tasks and the Gradle build is up to date.
// ---------------------------------------------------------------------------

val repoRoot: File = rootProject.projectDir.parentFile
val homeDir: File = File(System.getProperty("user.home"))
val rustupBinDir: File? = System.getenv("RUSTUP_BIN_DIR")
    ?.takeIf { it.isNotBlank() }
    ?.let(::File)
val defaultCargoBinDir = File(homeDir, ".cargo/bin")
val localProperties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.isFile) {
        file.inputStream().use { load(it) }
    }
}
val configuredCargoDir = localProperties.getProperty("rust.cargoDir")
    ?.takeIf { it.isNotBlank() }
    ?.let(::File)
val rustPathDirs = listOfNotNull(
    configuredCargoDir,
    rustupBinDir,
    defaultCargoBinDir,
).map { it.absolutePath } + (System.getenv("PATH") ?: "")
val rustPath = rustPathDirs.joinToString(File.pathSeparator)
val cargoExecutable = listOfNotNull(configuredCargoDir, rustupBinDir, defaultCargoBinDir)
    .map { File(it, "cargo") }
    .firstOrNull { it.canExecute() }
    ?: (System.getenv("PATH") ?: "").split(File.pathSeparator)
        .filter { it.isNotBlank() }
        .map { File(it, "cargo") }
        .firstOrNull { it.canExecute() }
    ?: File("cargo")
val cargoTargetDir = System.getenv("CARGO_TARGET_DIR")
val rustProfileIsRelease = gradle.startParameter.taskNames.any {
    it.contains("Release", ignoreCase = true)
}

val jniLibsDir = layout.projectDirectory.dir("src/main/jniLibs")
val uniffiKotlinDir = layout.buildDirectory.dir("generated/uniffi/kotlin")
val uniffiLibrary = jniLibsDir.file("arm64-v8a/libfriendlypass_mobile.so")
val rustSourceInputs = fileTree(repoRoot) {
    include("Cargo.toml")
    include("Cargo.lock")
    include("crates/friendlypass-mobile/**")
    include("crates/friendlypass-passkey/**")
    include("crates/friendlypass/src/**")
    include("crates/friendlypass/Cargo.toml")
    include("crates/friendlypass-passkey/Cargo.toml")
}

fun Exec.configureRustEnvironment() {
    environment("PATH", rustPath)
    if (cargoTargetDir != null) {
        environment("CARGO_TARGET_DIR", cargoTargetDir)
    }
}

val cargoNdkBuild = tasks.register<Exec>("cargoNdkBuild") {
    group = "rust"
    description = "Cross-compiles friendlypass_mobile for Android with cargo-ndk"
    workingDir = repoRoot
    val arguments = mutableListOf(
        "ndk",
        "-t", "arm64-v8a",
        "-t", "x86_64",
        "-o", jniLibsDir.asFile.absolutePath,
        "build",
        "-p", "friendlypass-mobile",
    )
    if (rustProfileIsRelease) {
        arguments += "--release"
    }
    commandLine(listOf(cargoExecutable.absolutePath) + arguments)
    configureRustEnvironment()

    inputs.property("releaseProfile", rustProfileIsRelease)
    inputs.files(rustSourceInputs)
    outputs.dir(jniLibsDir)
}

val uniffiBindgen = tasks.register<Exec>("uniffiBindgen") {
    group = "rust"
    description = "Generates Kotlin UniFFI bindings from the built Android library"
    dependsOn(cargoNdkBuild)
    workingDir = repoRoot
    commandLine(
        cargoExecutable.absolutePath,
        "run",
        "-p", "friendlypass-mobile",
        "--features", "bindgen",
        "--bin", "uniffi-bindgen",
        "--",
        "generate",
        "--library", uniffiLibrary.asFile.absolutePath,
        "--language", "kotlin",
        "--out-dir", uniffiKotlinDir.get().asFile.absolutePath,
        "--no-format",
    )
    configureRustEnvironment()

    inputs.property("releaseProfile", rustProfileIsRelease)
    inputs.files(rustSourceInputs)
    inputs.file(uniffiLibrary)
    outputs.dir(uniffiKotlinDir)
}

tasks.matching { it.name == "preBuild" }.configureEach {
    dependsOn(cargoNdkBuild, uniffiBindgen)
}

// The instrumented tests drive two companion apps (:testapp for autofill, :credtest for the
// Credential Manager). Install them on the same device first so a fresh emulator works with one
// command. Without ANDROID_SERIAL Gradle's install tasks target every connected device, exactly
// like connectedDebugAndroidTest itself.
tasks.matching { it.name == "connectedDebugAndroidTest" }.configureEach {
    dependsOn(":testapp:installDebug", ":credtest:installDebug")
}

android {
    namespace = "org.friendlypass.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.friendlypass.android"
        minSdk = 30
        targetSdk = 36
        versionCode = appVersionCode
        versionName = appVersionName

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (releaseKeystorePath != null) {
            create("release") {
                storeFile = file(releaseKeystorePath)
                storeType = releaseKeystoreType
                storePassword = requireNotNull(System.getenv("FP_ANDROID_KEYSTORE_PASSWORD")) {
                    "FP_ANDROID_KEYSTORE_PASSWORD must be set when FP_ANDROID_KEYSTORE is set"
                }
                keyAlias = requireNotNull(System.getenv("FP_ANDROID_KEY_ALIAS")) {
                    "FP_ANDROID_KEY_ALIAS must be set when FP_ANDROID_KEYSTORE is set"
                }
                keyPassword = requireNotNull(System.getenv("FP_ANDROID_KEY_PASSWORD")) {
                    "FP_ANDROID_KEY_PASSWORD must be set when FP_ANDROID_KEYSTORE is set"
                }
            }
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    buildTypes {
        release {
            // R8: the release build is the only place the shrinker + UniFFI/JNA keep rules are exercised.
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (releaseKeystorePath != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            kotlin.srcDir(uniffiKotlinDir.get().asFile)
        }
    }

    packaging {
        // JNA ships its native libraries as shared objects; keep them uncompressed
        // so the UniFFI bridge can load them straight from the APK.
        jniLibs.useLegacyPackaging = true
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons.core)
    debugImplementation(libs.compose.ui.tooling)

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.navigation.compose)

    implementation(libs.kotlinx.coroutines.android)

    implementation(libs.androidx.biometric)
    implementation(libs.androidx.autofill)
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.credentials.play.services.auth)
    implementation(libs.androidx.documentfile)

    // UniFFI's JVM bindings load the Rust cdylib through JNA.
    implementation(libs.jna) { artifact { type = "aar" } }

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)

    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation(libs.compose.ui.test.junit4)
    debugImplementation(libs.compose.ui.test.manifest)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.espresso.core)
    androidTestImplementation(libs.androidx.test.uiautomator)
    androidTestImplementation(libs.kotlinx.coroutines.test)
}
