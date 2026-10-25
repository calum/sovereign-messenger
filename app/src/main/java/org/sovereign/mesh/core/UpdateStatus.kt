package org.sovereign.mesh.core

import uniffi.rust_core.FacadeException

/**
 * Text the update screen shows for a failed receive. Fixed sentences only: the
 * exception message is never shown, so nothing from the core reaches the screen
 * through an error.
 */
fun updateStatusText(error: Throwable): String =
    when (error) {
        is FacadeException.AuthFailed ->
            "The update was refused: its signature did not verify. Do not install it."
        is FacadeException.Downgraded ->
            "This update is not newer than the installed version. It was refused; nothing was installed."
        is FacadeException.Malformed ->
            "The update was malformed or its signature was the wrong length. It was refused."
        is FacadeException.Network ->
            "No update was received. Check that both phones are on the same Wi-Fi and try again."
        else -> "Something went wrong. No update was installed."
    }

/**
 * Text the update screen shows for a failed send. Fixed sentences only, as for
 * the receive path. The sender never sees the receiver's verdict; the text says
 * what the sender can know.
 */
fun sendStatusText(error: Throwable): String =
    when (error) {
        is FacadeException.Malformed ->
            "The bundle was refused before sending: the signature file or the APK is the wrong size or type."
        is FacadeException.Network ->
            "Could not reach the other phone. Check the address, that both phones are on the same Wi-Fi, and that it is waiting on the Receive update screen."
        else -> "Something went wrong. Nothing was sent."
    }
