package io.homeassistant.companion.android.common.cfaccess

/**
 * Response from the cf-manager mint endpoint
 * POST https://mint.homelab.internal/mint
 */
data class CfMintResponse(
    val client_id: String,
    val client_secret: String,
    val expires_at: String,
)
