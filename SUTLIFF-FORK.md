# Home Assistant Companion for Android (Sutliff fork)

This is a **Sutliff fork** of the official
[Home Assistant Companion for Android](https://github.com/home-assistant/android).

## What we changed

- **Runtime CF Access token minting** — no tokens embedded in the APK. The app
  mints a per-device CF Access service token from `mint.homelab.internal` (LAN-only)
  on first run at home, stores it encrypted behind a TEE/StrongBox-backed Android
  Keystore key with `setUserAuthenticationRequired(true)`, and gates unlock on
  `BiometricPrompt` (fingerprint). The OkHttp interceptor (`CfHeaderInterceptor`)
  adds the `Cf-Access-Client-Id` + `Cf-Access-Client-Secret` headers to every
  request to `*.ffilt.us` hosts (REST, WebSocket, Coil, ExoPlayer — all share
  the same OkHttp client).

- **Telemetry** — one POST to `telemetry.ffilt.us` on app start, no auth, public.

- **Branding** — app version string + package unchanged so it drops into the
  same slot as the official client.

- **CI** — memory-capped build (`-Xmx3072m`, no daemon, 2 workers) on the
  `android`-labeled Gitea Actions runner. No CI-mint step (we moved that to
  runtime).

## Architecture

```
[app first run at home]
    │
    ▼  POST /mint  {app: "home-assistant", device_id: <ANDROID_ID>}
https://mint.homelab.internal (LAN-only, never tunneled)
    │
    │   cf-manager: mints CF Access service token (per app+device)
    │
    ▼  {client_id, client_secret, expires_at}
[CfTokenStore]
    │
    │  DEK: random 32 bytes
    │  KEK: Android Keystore AES-256-GCM, setUserAuthenticationRequired(true),
    │       AUTH_BIOMETRIC_STRONG, invalidatedByBiometricEnrollment
    │
    │  cipher = AES-GCM(KEK, dek)
    │  wrapped_token = AES-GCM(DEK, plaintext_token)
    │
    ▼  SharedPreferences[wrapped_dek_b64, ciphertext_b64, client_id, expires_at]
[on app use]
    │
    │  BiometricPrompt → KEK unwrap → DEK unwrap → plaintext token
    │
    ▼
[CfAccessTokenGate] (in-memory cache, lifetime of OkHttpClient)
    │
    ▼
[OkHttp Interceptor] → adds headers to *.ffilt.us requests
```

## Files added

- `common/src/main/kotlin/io/homeassistant/companion/android/common/cfaccess/CfMintResponse.kt`
- `common/src/main/kotlin/io/homeassistant/companion/android/common/cfaccess/CfTokenStore.kt`
- `common/src/main/kotlin/io/homeassistant/companion/android/common/cfaccess/CfAccessTokenGate.kt`
- `common/src/main/kotlin/io/homeassistant/companion/android/common/cfaccess/MintClient.kt`
- `common/src/main/kotlin/io/homeassistant/companion/android/common/cfaccess/CfHeaderInterceptor.kt`
- `common/src/main/kotlin/io/homeassistant/companion/android/di/CfAccessModule.kt` (Hilt multibinding)

## CI

See `.gitea/workflows/build-apk.yaml` — the in-cluster Gitea Actions runner
(ns `gitea-runner`, label `android`) builds a debug APK on every push to
`sutliff/*` branches and on `workflow_dispatch`. Manual dispatch supports
`debug` or `release`. No CI-mint step — tokens are runtime-only.

## Related docs

- `architecture/app-secret-minting.md` — the design doc
- `architecture/apk-build-pipeline.md` — the CI build pipeline
- `ops/rook-soul.md` — Rook's ops identity
