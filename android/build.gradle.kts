// Root build file: declare the plugins once, apply them in :app.
// Kotlin itself is provided by AGP's built-in Kotlin support (AGP 9+); only the
// Compose compiler plugin has to be applied on top of it.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.compose) apply false
}
