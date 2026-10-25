package org.sovereign.mesh.core

/**
 * Wraps the 32-byte vault data key with a key that never leaves secure hardware
 * where the phone has it. The app stores only the wrapped bytes. Kept as an
 * interface so the vault logic runs on the JVM, where there is no Android Keystore.
 */
interface KeyWrapper {
    /** Returns bytes safe to store. Throws if the wrapping key is unavailable. */
    fun wrap(plain: ByteArray): ByteArray

    /** Inverse of [wrap]. Throws if the wrapping key is gone or the bytes were changed. */
    fun unwrap(wrapped: ByteArray): ByteArray

    /** Destroys the wrapping key, so stored wrapped keys can never be opened again. */
    fun deleteKey()
}
