package io.homeassistant.companion.android.common.cfaccess

import android.content.Context
import android.provider.Settings
import android.util.Log
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory
import timber.log.Timber
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.serialization.json.Json

/**
 * Client for the cf-manager mint service at mint.homelab.internal.
 * Mints per-device CF Access service tokens for this app (home-assistant).
 *
 * Minting is fire-and-forget on first run: the result is stored in CfTokenStore.
 * The service is LAN-only (never exposed over the tunnel).
 */
@Singleton
class MintClient @Inject constructor(
    @ApplicationContext private val context: Context,
    private val tokenStore: CfTokenStore,
) {
    companion object {
        private const val TAG = "MintClient"
        // The cf-manager service inside the cluster — resolves via split-DNS on LAN
        private const val MINT_BASE = "https://mint.homelab.internal"
        // The app identifier used in the mint request
        const val APP_NAME = "home-assistant"
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
        .readTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
        .build()
    private val json = Json { ignoreUnknownKeys = true; coerceInputValues = true }

    /**
     * The device identifier for minting. Uses ANDROID_ID — unique per app-install,
     * stable across reboots, not user-visible.
     */
    private val deviceId: String by lazy {
        Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
            ?: java.util.UUID.randomUUID().toString()
    }

    /**
     * Attempts to mint and store a CF Access token. Idempotent — the cf-manager
     * returns the same token for the same (app, device_id) pair.
     *
     * Call this on first app launch or whenever hasToken() returns false.
     * Failures are silent (no crash, no UI) — the user can still use the app
     * if a token was previously stored and unlocked.
     */
    fun mintIfNeeded(onComplete: ((Boolean) -> Unit)? = null) {
        if (tokenStore.hasToken()) {
            Timber.d("MintClient: token already stored, skipping mint")
            onComplete?.invoke(true)
            return
        }

        scope.launch {
            try {
                Timber.d("MintClient: minting token for device=$deviceId")
                val response = doMint()
                if (response != null) {
                    tokenStore.storeToken(
                        clientId = response.client_id,
                        clientSecret = response.client_secret,
                        expiresAt = response.expires_at,
                    )
                    Timber.i("MintClient: mint succeeded, token stored (expires ${response.expires_at})")
                    onComplete?.invoke(true)
                } else {
                    Timber.w("MintClient: mint returned null response")
                    onComplete?.invoke(false)
                }
            } catch (e: Exception) {
                Timber.e(e, "MintClient: mint failed")
                onComplete?.invoke(false)
            }
        }
    }

    /**
     * Blocking mint — use from coroutine context only.
     */
    suspend fun mintBlocking(): Boolean = withContext(Dispatchers.IO) {
        try {
            val response = doMint()
            if (response != null) {
                tokenStore.storeToken(response.client_id, response.client_secret, response.expires_at)
                Timber.i("MintClient: mint succeeded (blocking)")
                true
            } else {
                Timber.w("MintClient: mint returned null")
                false
            }
        } catch (e: Exception) {
            Timber.e(e, "MintClient: mint failed (blocking)")
            false
        }
    }

    /**
     * Revokes the stored token for this device. Call when user logs out or resets.
     */
    fun revokeStored() {
        tokenStore.clearToken()
    }

    private suspend fun doMint(): CfMintResponse? = withContext(Dispatchers.IO) {
        try {
            val body = """
                {"app": "$APP_NAME", "device_id": "$deviceId"}
            """.trimIndent()
            val requestBody = body.toRequestBody("application/json".toMediaType())
            val request = Request.Builder()
                .url("$MINT_BASE/mint")
                .post(requestBody)
                .build()

            val response = httpClient.newCall(request).execute()
            val bodyStr = response.body?.string() ?: return@withContext null

            if (!response.isSuccessful) {
                Timber.w("MintClient: mint request failed ${response.code}: $bodyStr")
                return@withContext null
            }

            json.decodeFromString<CfMintResponse>(bodyStr)
        } catch (e: Exception) {
            Timber.e(e, "MintClient: mint request exception (device is likely off LAN)")
            null
        }
    }
}
