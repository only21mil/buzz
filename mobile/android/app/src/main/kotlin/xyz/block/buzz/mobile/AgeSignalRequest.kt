package xyz.block.buzz.mobile

import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/** The Google-free Android build cannot provide Play age signals. */
internal object AgeSignalRequest : MethodChannel.MethodCallHandler {
    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "requestAgeSignal" -> result.success(
                mapOf("status" to "unavailable", "ageUpper" to null),
            )
            else -> result.notImplemented()
        }
    }
}
