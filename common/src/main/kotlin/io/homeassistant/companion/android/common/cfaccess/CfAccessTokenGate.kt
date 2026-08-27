package io.homeassistant.companion.android.common.cfaccess

/**
 * A shared gate that holds the decrypted CF Access token after successful biometric auth.
 * The token is loaded once per app session (after user authenticates) and cached here.
 * The CfHeaderInterceptor reads from this gate; the UI layer (Activity) calls
 * [unlockFromActivity] to populate it.
 *
 * Thread-safe: all access goes through a single Mutex.
 */
@Singleton
class CfAccessTokenGate @javax.inject.Inject constructor(
    private val tokenStore: CfTokenStore,
) {
    @Volatile
    private var token: Pair<String, String>? = null

    /**
     * Returns the cached token, or null if not yet unlocked this session.
     */
    fun get(): Pair<String, String>? = token

    /**
     * Checks if a token exists in the token store (persisted from a previous mint).
     */
    fun hasPersistedToken(): Boolean = tokenStore.hasToken()

    /**
     * Checks if the token has been unlocked this session.
     */
    fun isUnlocked(): Boolean = token != null

    /**
     * Clears the cached token (e.g. on logout).
     */
    fun clear() {
        token = null
    }

    /**
     * Returns the cached token, or attempts biometric unlock via the provided Activity.
     * Call this from a FragmentActivity (typically onResume or after onboarding).
     *
     * Returns the token pair on success, throws SecurityException on failure.
     */
    suspend fun unlockFromActivity(activity: FragmentActivity): Pair<String, String> {
        token?.let { return it }
        val result = tokenStore.unlockWithBiometric(activity)
        token = result
        return result
    }
}
