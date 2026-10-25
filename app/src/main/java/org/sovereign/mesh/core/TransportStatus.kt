package org.sovereign.mesh.core

import uniffi.rust_core.FacadeException

/**
 * Text the chat screen shows for a failed transport call. Each core error maps
 * to a fixed sentence. The message from the exception is never shown, so no
 * key or plaintext can reach the screen through an error.
 */
fun transportStatusText(error: Throwable): String =
    when (error) {
        is FacadeException.NoLink -> "Not connected to this contact yet."
        is FacadeException.NoSession -> "No session with this contact yet."
        is FacadeException.NotPinned -> "Scan this contact's QR code first."
        is FacadeException.Network -> "Connection failed or was lost."
        is FacadeException.TorUnavailable -> "Tor is not running."
        is FacadeException.AuthFailed -> "A message failed authentication and was dropped."
        is FacadeException.Malformed -> "A message was malformed and was dropped."
        else -> "Something went wrong."
    }
