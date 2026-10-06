# Go calls the gomobile bindings, and the app's implementations of their
# interfaces, through JNI by name: keep them as they are.
-keep class go.** { *; }
-keep class dev.idfoundry.oid4vcwallet.gomobile.** { *; }
-keep class * implements dev.idfoundry.oid4vcwallet.gomobile.** { *; }
