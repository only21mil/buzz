package xyz.block.buzz.mobile

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * OS device-auth prompt behind the `buzz/device_auth` method channel.
 *
 * The Dart export gate calls `canAuthenticate` before showing the recovery
 * page action and `authenticate` at the actual key read/publish step. Every
 * outcome maps to a typed error the Dart side fails closed on:
 * `cancelled` (user backed out), `not_available` (no secure lock / no
 * hardware), anything else surfaces as a generic failure.
 *
 * Framework APIs only (BiometricPrompt on API 29+, Keyguard confirm
 * credential below that) so pairing QR scanning keeps its Google-free
 * dependency path: no extra biometric library, no ML Kit, no Play Services.
 */
internal class DeviceAuthBridge(
    private val activity: MainActivity,
    binaryMessenger: BinaryMessenger,
) {
    private val channel = MethodChannel(binaryMessenger, METHOD_CHANNEL)
    private var pendingResult: MethodChannel.Result? = null
    private var cancellationSignal: CancellationSignal? = null

    init {
        channel.setMethodCallHandler(::handleMethodCall)
    }

    fun handleActivityResult(
        requestCode: Int,
        resultCode: Int,
    ) {
        if (requestCode != CONFIRM_CREDENTIAL_REQUEST_CODE) return
        val result = pendingResult ?: return
        pendingResult = null
        if (resultCode == android.app.Activity.RESULT_OK) {
            result.success(true)
        } else {
            result.error(
                "cancelled",
                "Device verification was cancelled.",
                null,
            )
        }
    }

    fun dispose() {
        channel.setMethodCallHandler(null)
        cancellationSignal?.cancel()
        cancellationSignal = null
        pendingResult?.error(
            "activity_unavailable",
            "The device verification request was interrupted.",
            null,
        )
        pendingResult = null
    }

    private fun handleMethodCall(
        call: MethodCall,
        result: MethodChannel.Result,
    ) {
        when (call.method) {
            CAN_AUTHENTICATE_METHOD -> withNoArguments(call, result) {
                result.success(canAuthenticate())
            }
            AUTHENTICATE_METHOD -> authenticate(call.arguments, result)
            else -> result.notImplemented()
        }
    }

    private fun withNoArguments(
        call: MethodCall,
        result: MethodChannel.Result,
        action: () -> Unit,
    ) {
        if (call.arguments != null) {
            result.error(
                "invalid_arguments",
                "${call.method} does not accept arguments.",
                null,
            )
            return
        }
        action()
    }

    private fun keyguardManager(): KeyguardManager =
        activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

    private fun canAuthenticate(): Boolean {
        // A secure lock screen (PIN/pattern/password, plus biometrics when
        // enrolled) is the requirement. Without one there is nothing to
        // prompt, so the Dart gate fails closed.
        return keyguardManager().isDeviceSecure
    }

    private fun authenticate(
        arguments: Any?,
        result: MethodChannel.Result,
    ) {
        if (pendingResult != null) {
            result.error(
                "auth_in_progress",
                "A device verification request is already in progress.",
                null,
            )
            return
        }
        val reason = (arguments as? Map<*, *>)?.get("reason") as? String
        if (reason.isNullOrBlank()) {
            result.error(
                "invalid_arguments",
                "authenticate requires a non-empty reason.",
                null,
            )
            return
        }
        if (!canAuthenticate()) {
            result.error(
                "not_available",
                "This device has no secure lock screen.",
                null,
            )
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            authenticateWithBiometricPrompt(reason, result)
        } else {
            authenticateWithConfirmCredential(reason, result)
        }
    }

    private fun authenticateWithBiometricPrompt(
        reason: String,
        result: MethodChannel.Result,
    ) {
        val signal = CancellationSignal()
        cancellationSignal = signal
        pendingResult = result
        try {
            val prompt = BiometricPrompt.Builder(activity)
                .setTitle("Confirm it's you")
                .setSubtitle(reason)
                .setDescription("Use your fingerprint, face, or lock screen.")
                .setDeviceCredentialAllowed(true)
                .build()
            prompt.authenticate(
                signal,
                activity.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(
                        resultValue: BiometricPrompt.AuthenticationResult?,
                    ) {
                        settleSuccess()
                    }

                    override fun onAuthenticationFailed() {
                        // Per-attempt mismatch (e.g. partial fingerprint);
                        // the system keeps the prompt up for retries.
                    }

                    override fun onAuthenticationError(
                        errorCode: Int,
                        errString: CharSequence?,
                    ) {
                        settleError(errorCode, errString?.toString())
                    }
                },
            )
        } catch (_: RuntimeException) {
            pendingResult = null
            cancellationSignal = null
            result.error(
                "not_available",
                "Device verification is unavailable.",
                null,
            )
        }
    }

    private fun authenticateWithConfirmCredential(
        reason: String,
        result: MethodChannel.Result,
    ) {
        val intent = keyguardManager().createConfirmDeviceCredentialIntent(
            "Confirm it's you",
            reason,
        )
        if (intent == null) {
            result.error(
                "not_available",
                "This device has no secure lock screen.",
                null,
            )
            return
        }
        pendingResult = result
        try {
            activity.startActivityForResult(intent, CONFIRM_CREDENTIAL_REQUEST_CODE)
        } catch (_: RuntimeException) {
            pendingResult = null
            result.error(
                "not_available",
                "Device verification could not start.",
                null,
            )
        }
    }

    private fun settleSuccess() {
        val result = pendingResult ?: return
        pendingResult = null
        cancellationSignal = null
        result.success(true)
    }

    private fun settleError(
        errorCode: Int,
        message: String?,
    ) {
        val result = pendingResult ?: return
        pendingResult = null
        cancellationSignal = null
        val code = when (errorCode) {
            BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED -> "cancelled"
            BiometricPrompt.BIOMETRIC_ERROR_CANCELED -> "cancelled"
            BiometricPrompt.BIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL,
            BiometricPrompt.BIOMETRIC_ERROR_NO_BIOMETRICS,
            BiometricPrompt.BIOMETRIC_ERROR_HW_UNAVAILABLE,
            BiometricPrompt.BIOMETRIC_ERROR_NO_SPACE,
            BiometricPrompt.BIOMETRIC_ERROR_UNABLE_TO_PROCESS,
            -> "not_available"
            else -> "auth_failed"
        }
        result.error(code, message ?: "Device verification did not pass.", null)
    }

    private companion object {
        const val METHOD_CHANNEL = "buzz/device_auth"
        const val CAN_AUTHENTICATE_METHOD = "canAuthenticate"
        const val AUTHENTICATE_METHOD = "authenticate"
        const val CONFIRM_CREDENTIAL_REQUEST_CODE = 28032
    }
}
