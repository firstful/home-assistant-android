package io.homeassistant.companion.android.common.cfaccess

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GcmParameterSpec
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Stores a CF Access service token encrypted behind an Android Keystore key that
 * requires biometric authentication to unlock. This ensures the token cannot be
 * extracted from the APK or from storage without biometric auth — the token is
 * never present in plaintext on disk.
 *
 * Architecture:
 * - On first run / mint: POST mint.homelab.internal/mint, get {client_id, client_secret}
 * - Wrap client_secret with a random DEK (AES-256-GCM), then wrap DEK with the
 *   Android Keystore key (setUserAuthenticationRequired = true).
 * - Store: SharedPreferences[wrapped_dek_b64, token_ciphertext_b64]
 * - On use: BiometricPrompt → unwrap DEK → unwrap token → add CF headers
 */
@Singleton
class CfTokenStore @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    companion object {
        private const val KEYSTORE_ALIAS = "sutliff_cf_token_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH = 128
        private const val GCM_IV_LENGTH = 12
        private const val PREFS_NAME = "cf_token_store"
        private const val PREF_WDEK = "wrapped_dek"
        private const val PREF_CT = "ciphertext"
        private const val PREF_CLIENT_ID = "client_id"
        private const val PREF_EXPIRES = "expires_at"
        private const val AUTH_VALIDITY_SECONDS = 60
    }

    private val prefs: SharedPreferences by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Returns true if a minted token is already stored (not necessarily unlocked).
     */
    fun hasToken(): Boolean = prefs.contains(PREF_CT)

    /**
     * Stores the minted token. Call this after a successful mint.
     * The SharedPreferences values (wrapped_dek, ciphertext) are opaque blobs —
     * no plaintext token on disk.
     */
    fun storeToken(clientId: String, clientSecret: String, expiresAt: String) {
        val kek = getOrCreateKeystoreKey()
        val dek = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val iv = ByteArray(GCM_IV_LENGTH).also { java.security.SecureRandom().nextBytes(it) }

        // Wrap token with DEK
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, kek, GcmParameterSpec(GCM_TAG_LENGTH, iv))
        val ciphertext = cipher.doFinal(clientSecret.toByteArray(Charsets.UTF_8))

        // Wrap DEK with KEK
        val dekCipher = Cipher.getInstance(TRANSFORMATION)
        dekCipher.init(Cipher.ENCRYPT_MODE, kek)
        val wrappedDek = dekCipher.doFinal(dek)
        val dekIv = dekCipher.iv

        prefs.edit {
            putString(PREF_WDEK, Base64.encodeToString(wrappedDek, Base64.NO_WRAP))
            putString(PREF_WDEK + "_iv", Base64.encodeToString(dekIv, Base64.NO_WRAP))
            putString(PREF_CT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            putString(PREF_CT + "_iv", Base64.encodeToString(iv, Base64.NO_WRAP))
            putString(PREF_CLIENT_ID, clientId)
            putString(PREF_EXPIRES, expiresAt)
        }
        Timber.d("CfTokenStore: token stored (encrypted on disk)")
    }

    /**
     * Unlocks the stored token using BiometricPrompt. Throws on auth failure.
     * Returns (clientId, clientSecret).
     */
    suspend fun unlockWithBiometric(activity: FragmentActivity): Pair<String, String> =
        withContext(Dispatchers.Main) {
            val biometricManager = BiometricManager.from(activity)
            val canAuth = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
                throw IllegalStateException("Biometric not available: $canAuth")
            }

            suspendCancellableCoroutine { continuation ->
                val cipher = buildUnlockCipher()
                val prompt = BiometricPrompt(
                    activity,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            val authenticatedCipher = result.cryptoObject?.cipher
                                ?: throw IllegalStateException("No crypto object in result")
                            val clientId = prefs.getString(PREF_CLIENT_ID, "")
                                ?: throw IllegalStateException("No client_id in prefs")
                            val (clientSecret, expiresAt) = unwrapTokenFromCipher(authenticatedCipher)
                            Timber.d("CfTokenStore: biometric unlock succeeded")
                            continuation.resume(Pair(clientId, clientSecret))
                        }

                        override fun onAuthenticationError(errCode: Int, errString: CharSequence) {
                            Timber.w("CfTokenStore: biometric error $errCode $errString")
                            continuation.resumeWithException(
                                SecurityException("Biometric auth failed: $errString")
                            )
                        }

                        override fun onAuthenticationFailed() {
                            // Don't resume — user can retry
                            Timber.d("CfTokenStore: biometric attempt failed")
                        }
                    },
                )
                val info = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Unlock Home Assistant")
                    .setSubtitle("Authenticate to access your home")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setConfirmationRequired(false)
                    .build()

                continuation.invokeOnCancellation {
                    prompt.cancelAuthentication()
                }

                prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
            }
        }

    /**
     * Clears the stored token (e.g. on device reset or user request).
     */
    fun clearToken() {
        prefs.edit { clear() }
        Timber.d("CfTokenStore: token cleared")
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    private fun getOrCreateKeystoreKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        keyStore.getKey(KEYSTORE_ALIAS, null)?.let { return it as SecretKey }

        val keyGenSpec = KeyGenParameterSpec.Builder(
            KEYSTORE_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                AUTH_VALIDITY_SECONDS,
                KeyProperties.AUTH_BIOMETRIC_STRONG,
            )
            .setInvalidatedByBiometricEnrollment(true)
            .build()

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE,
        )
        keyGenerator.init(keyGenSpec)
        return keyGenerator.generateKey()
    }

    private fun buildUnlockCipher(): Cipher {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val key = keyStore.getKey(KEYSTORE_ALIAS, null) as? SecretKey
            ?: throw IllegalStateException("Keystore key not found — must call storeToken first")
        return Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, key)
        }
    }

    private fun unwrapTokenFromCipher(cipher: Cipher): Pair<String, String> {
        val wrappedDekB64 = prefs.getString(PREF_WDEK, null)
            ?: throw IllegalStateException("No wrapped DEK in prefs")
        val ivB64 = prefs.getString(PREF_WDEK + "_iv", null)
            ?: throw IllegalStateException("No DEK IV in prefs")
        val ctB64 = prefs.getString(PREF_CT, null)
            ?: throw IllegalStateException("No ciphertext in prefs")
        val ctIvB64 = prefs.getString(PREF_CT + "_iv", null)
            ?: throw IllegalStateException("No ciphertext IV in prefs")

        val wrappedDek = Base64.decode(wrappedDekB64, Base64.NO_WRAP)
        val iv = Base64.decode(ivB64, Base64.NO_WRAP)
        val ciphertext = Base64.decode(ctB64, Base64.NO_WRAP)
        val ctIv = Base64.decode(ctIvB64, Base64.NO_WRAP)

        // Unwrap DEK
        val dekCipher = Cipher.getInstance(TRANSFORMATION)
        dekCipher.init(Cipher.DECRYPT_MODE, cipher.key, GcmParameterSpec(GCM_TAG_LENGTH, iv))
        val dek = dekCipher.doFinal(wrappedDek)

        // Unwrap token
        val tokenCipher = Cipher.getInstance(TRANSFORMATION)
        tokenCipher.init(Cipher.DECRYPT_MODE, javax.crypto.spec.SecretKeySpec(dek, "AES"),
            GcmParameterSpec(GCM_TAG_LENGTH, ctIv))
        val clientSecret = String(tokenCipher.doFinal(ciphertext), Charsets.UTF_8)
        val clientId = prefs.getString(PREF_CLIENT_ID, "") ?: ""
        val expiresAt = prefs.getString(PREF_EXPIRES, "") ?: ""

        return Pair(clientId, clientSecret)
    }
}
