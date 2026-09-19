package xyz.block.buzz.mobile

import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail

class AgeSignalRequestTest {
    @Test
    fun `age signal channel always reports unavailable without an SDK`() {
        repeat(2) {
            val result = RecordingResult()
            AgeSignalRequest.onMethodCall(MethodCall("requestAgeSignal", null), result)
            assertEquals(listOf<Any?>(mapOf("status" to "unavailable", "ageUpper" to null)), result.replies)
            assertEquals(0, result.notImplementedCount)
        }
    }

    @Test
    fun `unknown channel methods remain unimplemented`() {
        val result = RecordingResult()
        AgeSignalRequest.onMethodCall(MethodCall("unknownMethod", null), result)
        assertEquals(emptyList(), result.replies)
        assertEquals(1, result.notImplementedCount)
    }

    private class RecordingResult : MethodChannel.Result {
        val replies = mutableListOf<Any?>()
        var notImplementedCount = 0

        override fun success(result: Any?) {
            replies.add(result)
        }

        override fun error(code: String, message: String?, details: Any?) {
            fail("Unexpected platform error: $code")
        }

        override fun notImplemented() {
            notImplementedCount += 1
        }
    }
}
