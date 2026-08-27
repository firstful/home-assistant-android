package io.homeassistant.companion.android.common.cfaccess

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import io.homeassistant.companion.android.di.OkHttpConfigurator
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Response
import timber.log.Timber
import javax.inject.Inject
import javax.inject.Singleton

/**
 * OkHttp interceptor that injects Cloudflare Access service-token headers
 * (Cf-Access-Client-Id, Cf-Access-Client-Secret) into outbound requests.
 *
 * Only applies to requests to *.ffilt.us hosts — all other traffic is passed
 * through unmodified.
 *
 * The token is read from [CfAccessTokenGate] which is populated by the UI layer
 * (FragmentActivity) calling [CfAccessTokenGate.unlockFromActivity] on resume /
 * after onboarding. If no token is available the request proceeds without headers —
 * CF will deny access, resulting in a clear auth error rather than a crash.
 *
 * Exposed as an [OkHttpConfigurator] so Hilt's multibinding wires it into the
 * shared OkHttpClient with zero app-module changes.
 */
@Singleton
class CfHeaderInterceptor @Inject constructor(
    @ApplicationContext private val context: Context,
    private val tokenGate: CfAccessTokenGate,
) : Interceptor {

    companion object {
        private const val TAG = "CfHeaderInterceptor"
        private val FFILT_US_PATTERN = Regex(".*\\.ffilt\\.us$")
    }

    // Expose as OkHttpConfigurator
    fun asOkHttpConfigurator(): OkHttpConfigurator = OkHttpConfigurator { it.addInterceptor(this) }

    override fun intercept(chain: Interceptor.Chain): Response {
        val originalRequest = chain.request()
        val host = originalRequest.url.host

        // Only inject CF headers for *.ffilt.us hosts
        if (!host.matches(FFILT_US_PATTERN)) {
            return chain.proceed(originalRequest)
        }

        val token = tokenGate.get()
        if (token == null) {
            Timber.w("CfHeaderInterceptor: no token available for $host, proceeding without headers")
            return chain.proceed(originalRequest)
        }

        val authorizedRequest = originalRequest.newBuilder()
            .header("Cf-Access-Client-Id", token.first)
            .header("Cf-Access-Client-Secret", token.second)
            .build()

        return chain.proceed(authorizedRequest)
    }
}
