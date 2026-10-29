# Keep rules for release builds. Add rules only when R8 breaks something, and say why here.

# JNA's native library looks up Java fields and methods by name (for example
# Pointer.peer). If R8 renames them the app dies at startup with
# "UnsatisfiedLinkError: Can't obtain peer field ID for class com.sun.jna.Pointer".
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }

# The UniFFI bindings are JNA Structure/Callback subclasses whose field names and
# layout JNA reads by reflection.
-keep class uniffi.** { *; }
-dontwarn java.awt.*
