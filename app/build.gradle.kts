import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Release signing reads keystore.properties at the repo root (git-ignored).
// Without it, release builds are left unsigned rather than falling back to the debug key.
val keystoreFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystoreFile.exists()) keystoreFile.inputStream().use { load(it) }
}

android {
    namespace = "org.sovereign.mesh"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.sovereign.mesh"
        minSdk = 29
        targetSdk = 35
        versionCode = 6
        versionName = "0.2.4"
    }

    signingConfigs {
        create("release") {
            if (keystoreFile.exists()) {
                storeFile = file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (keystoreFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
}

// The UniFFI Kotlin bindings call rust-core through JNA. Android needs the
// @aar artifact (bundles the per-ABI JNI shim); the JVM test needs the plain jar.
val jnaVersion = "5.16.0"

// Host build of rust-core for JVM unit tests. UniFFI's generated code loads the
// library by path from this system property instead of by platform name.
val rustCoreDir = rootProject.file("rust-core")
val hostLibFile = when {
    System.getProperty("os.name").startsWith("Windows") -> "rust_core.dll"
    System.getProperty("os.name").startsWith("Mac") -> "librust_core.dylib"
    else -> "librust_core.so"
}
val cargoBuildHost by tasks.registering(Exec::class) {
    workingDir = rootProject.projectDir
    commandLine("cargo", "build", "--manifest-path", "rust-core/Cargo.toml", "--lib")
}
tasks.withType<Test>().configureEach {
    dependsOn(cargoBuildHost)
    systemProperty(
        "uniffi.component.rust_core.libraryOverride",
        rustCoreDir.resolve("target/debug/$hostLibFile").absolutePath,
    )
}

// The generated Kotlin loads the native library by the name written into rust_core.kt, and
// Android finds it only if the file in jniLibs has exactly that name. A mismatch builds fine
// and then crashes the app at launch with UnsatisfiedLinkError, and the JVM tests cannot see it
// because they load the library by path. So the build reads the name from the bindings and
// refuses to package an APK whose libraries are missing or named differently.
val verifyNativeLibraries by tasks.registering {
    val bindings = file("src/main/java/uniffi/rust_core/rust_core.kt")
    val jniLibs = file("src/main/jniLibs")
    doLast {
        val name = Regex("""findLibraryName[\s\S]*?return "([A-Za-z0-9_]+)""")
            .find(bindings.readText())?.groupValues?.get(1)
            ?: throw GradleException("Could not read the native library name from $bindings")
        val missing = listOf("arm64-v8a", "x86_64").filter { !File(jniLibs, "$it/lib$name.so").isFile }
        if (missing.isNotEmpty()) {
            val found = jniLibs.walkTopDown().filter { it.isFile }.map { it.relativeTo(jniLibs).path }.toList()
            throw GradleException(
                "The bindings load lib$name.so but it is missing for: ${missing.joinToString()}. " +
                    "Found in jniLibs: ${found.ifEmpty { listOf("nothing") }.joinToString()}. " +
                    "Run: mise run rust:android",
            )
        }
    }
}
tasks.matching { it.name.startsWith("merge") && it.name.endsWith("JniLibFolders") }
    .configureEach { dependsOn(verifyNativeLibraries) }

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("net.java.dev.jna:jna:$jnaVersion@aar")
    // QR encode and decode (core only, no Android-specific ZXing). Released 2024-01-31.
    implementation("com.google.zxing:core:3.5.3")
    // CameraX for the pairing scanner. 1.4.2 (published 2025-03-26) works with AGP 8.7.3
    // and compileSdk 35; 1.6.x needs AGP 8.9.1 and compileSdk 36, so it is not used.
    val cameraVersion = "1.4.2"
    implementation("androidx.camera:camera-core:$cameraVersion")
    implementation("androidx.camera:camera-camera2:$cameraVersion")
    implementation("androidx.camera:camera-lifecycle:$cameraVersion")
    implementation("androidx.camera:camera-view:$cameraVersion")
    debugImplementation("androidx.compose.ui:ui-tooling")

    testImplementation("junit:junit:4.13.2")
    testImplementation("net.java.dev.jna:jna:$jnaVersion")
}
