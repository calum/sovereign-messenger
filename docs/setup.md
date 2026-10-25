# Setup and building

## What you need

You need:

- [mise](https://mise.jdx.dev) to run the project tasks,
- Rust (stable, via `rustup`),
- JDK 17 or newer,
- the Android SDK with platform 35, build-tools 35.0.0 and NDK 27.2.12479018.

Point Gradle at the SDK with a `local.properties` file in the repo root. Do not commit it:

```bash
sdk.dir=C\:\\Users\\<you>\\AppData\\Local\\Android\\Sdk
```

On Windows, double every backslash in that path, as above. Gradle reads `\` as an escape character.

## Building and testing

```bash
mise tasks            # list every task
mise run check        # lint and run all tests
mise run rust:test    # Rust unit tests only
mise run android:debug
```

The debug APK is written to `app/build/outputs/apk/debug/app-debug.apk`.

On Windows, copy `mise.local.toml.example` to `mise.local.toml` first and check the two paths in it, then run `mise trust`, so mise can find the NDK and JDK. The native build (`mise run rust:android`) must run under Git Bash; the mise task calls it for you, because `bash` in PowerShell is often WSL's. The build stops if the native library is missing or misnamed.

Tests: 207 Rust tests (239 with `--features tor`; `mise run rust:test:tor`) and 96 JVM tests, run on Linux. Three live Tor tests are ignored by default (`mise run rust:live`) and need an unfiltered internet connection.

To get it onto a phone on the same Wi-Fi (Windows only), run `mise run android:share`. It prints a download link and a QR code, then serves the APK on the laptop's Wi-Fi address until you press Ctrl+C. Anyone on that network who has the link can download the APK while it runs, so stop it when the install is done. `SERVE_IP` and `SERVE_PORT` override the address and port. The `qrcode` package is needed for the QR code (`pip install qrcode`).
