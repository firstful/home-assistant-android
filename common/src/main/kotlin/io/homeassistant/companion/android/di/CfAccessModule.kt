package io.homeassistant.companion.android.di

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dagger.multibindings.Multibinds
import io.homeassistant.companion.android.common.cfaccess.CfHeaderInterceptor
import javax.inject.Singleton

/**
 * Binds [CfHeaderInterceptor] into the [OkHttpConfigurator] multibinding set so
 * that the shared OkHttpClient picks it up automatically.
 *
 * No additional configuration is needed elsewhere — Hilt resolves the set of
 * configurators in [io.homeassistant.companion.android.common.data.HomeAssistantApis].
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class CfAccessModule {

    @Binds
    @Singleton
    internal abstract fun bindCfHeaderInterceptor(
        interceptor: CfHeaderInterceptor,
    ): OkHttpConfigurator

    @Multibinds
    abstract fun bindOkHttpClientConfigurator(): Set<@JvmSuppressWildcards OkHttpConfigurator>
}
