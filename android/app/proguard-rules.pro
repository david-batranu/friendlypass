# UniFFI-generated Kotlin bindings load the Rust cdylib through JNA. Both halves
# are reached only by reflection/native lookup, so R8 must keep their names.
-keep class uniffi.** { *; }
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}

# JNA references desktop-only classes that do not exist on Android.
-dontwarn java.awt.**
-dontwarn javax.swing.**
-dontwarn sun.misc.**
