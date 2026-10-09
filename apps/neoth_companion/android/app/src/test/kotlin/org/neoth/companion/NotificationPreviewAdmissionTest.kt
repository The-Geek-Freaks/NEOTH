package org.neoth.companion

import org.junit.Assert.*
import org.junit.Test

class NotificationPreviewAdmissionTest {
    private val wall = 1_000_000L
    private val elapsed = 10_000L
    private val allowed = PreviewPolicy(enabled = true, packages = setOf("com.whatsapp"))
    private fun candidate(key: String = "source", at: Long = wall + 1_000, packageName: String = "com.whatsapp") =
        PreviewCandidate(packageName, key, at, "A sender", "A message")
    private fun owner(policy: PreviewPolicy = allowed) = NotificationPreviewAdmission().also {
        it.configure(policy, "scope_a", wall, elapsed)
    }
    private fun admit(owner: NotificationPreviewAdmission, value: PreviewCandidate = candidate(),
        now: Long = wall + 1_000, tick: Long = elapsed + 1_000, minute: Int = 12 * 60,
        access: Boolean = true, foreground: Boolean = true, unlocked: Boolean = true) =
        owner.admit(value, now, tick, minute, access, foreground, unlocked)

    @Test fun disabledOrUnconfiguredOwnerRejects() {
        assertNull(admit(NotificationPreviewAdmission()))
        assertNull(admit(owner(PreviewPolicy())))
        assertNull(admit(owner(allowed.copy(packages = emptySet()))))
    }

    @Test fun permissionForegroundAndLockEachGateAdmission() {
        assertNull(admit(owner(), access = false))
        assertNull(admit(owner(), foreground = false))
        assertNull(admit(owner(), unlocked = false))
        assertNotNull(admit(owner()))
    }

    @Test fun everyPackageNeedsItsOwnExplicitSelection() {
        assertNull(admit(owner(), candidate(packageName = "com.whatsapp.w4b")))
        assertNull(admit(owner(), candidate(packageName = "org.telegram.messenger")))
        assertNull(admit(owner(), candidate(packageName = "com.example.other")))
        for (packageName in previewPackages.keys) {
            assertNotNull(admit(owner(allowed.copy(packages = setOf(packageName))), candidate(packageName = packageName)))
        }
    }

    @Test fun quietHoursHandleSameDayOvernightAndAllDay() {
        val daytime = owner(allowed.copy(quietHours = true, quietStart = 600, quietEnd = 660))
        assertNull(admit(daytime, minute = 600))
        assertNotNull(admit(daytime, minute = 660))
        val overnight = allowed.copy(quietHours = true, quietStart = 1320, quietEnd = 420)
        for (minute in listOf(1320, 1439, 0, 419)) assertNull(admit(owner(overnight), minute = minute))
        assertNotNull(admit(owner(overnight), minute = 420))
        assertNull(admit(owner(overnight.copy(quietEnd = 1320)), minute = 900))
        assertNull(admit(owner(), minute = -1))
    }

    @Test fun staleFutureAndPreConsentPostsReject() {
        assertNull(admit(owner(), candidate(at = wall - 1)))
        assertNull(admit(owner(), candidate(at = wall + 1_001)))
        assertNull(admit(owner(), candidate(at = wall), now = wall + 30_000, tick = elapsed + 30_000))
        assertNotNull(admit(owner(), candidate(at = wall), now = wall + 29_999, tick = elapsed + 29_999))
    }

    @Test fun originalDeadlineCannotBeExtendedByDelayedDelivery() {
        val value = admit(owner(), candidate(at = wall), now = wall + 29_000, tick = elapsed + 29_000)!!
        assertEquals(wall + 30_000, value.expiresAt)
        assertEquals(elapsed + 30_000, value.expiresElapsed)
    }

    @Test fun duplicateSourceDoesNotRefreshOrReplacePreview() {
        val admission = owner()
        val first = admit(admission)!!
        assertTrue(first.source.matches(Regex("[a-f0-9]{64}")))
        assertFalse(first.source.contains("source"))
        assertNull(admit(admission, candidate().copy(text = "Changed text"), now = wall + 2_000, tick = elapsed + 2_000))
        assertNotNull(admit(admission, candidate(at = wall + 2_000), now = wall + 2_000, tick = elapsed + 2_000))
    }

    @Test fun sourceIdentitySeparatesApps() {
        val policy = allowed.copy(packages = previewPackages.keys)
        val admission = owner(policy)
        val first = admit(admission)!!
        val second = admit(admission, candidate(packageName = "com.whatsapp.w4b"))!!
        assertNotEquals(first.source, second.source)
    }

    @Test fun fullReplayWindowDropsNewEntriesWithoutEvictingLiveIdentities() {
        val admission = owner()
        for (index in 0 until 128) assertNotNull(admit(admission, candidate(key = "source-$index")))
        assertNull(admit(admission, candidate(key = "overflow")))
        assertNull(admit(admission, candidate(key = "source-0")))
        assertNotNull(admit(admission, candidate(key = "new", at = wall + 31_001),
            now = wall + 31_001, tick = elapsed + 31_001))
    }

    @Test fun suspensionAndNewConsentCannotReplayAnEarlierEvent() {
        val admission = owner()
        assertNotNull(admit(admission))
        admission.suspend()
        assertNull(admit(admission, candidate(key = "second")))
        admission.configure(allowed, "scope_b", wall + 2_000, elapsed + 2_000)
        assertNull(admit(admission, candidate(key = "second"), now = wall + 2_000, tick = elapsed + 2_000))
        assertEquals("scope_b", admit(admission, candidate(key = "second", at = wall + 2_001),
            now = wall + 2_001, tick = elapsed + 2_001)!!.scope)
    }

    @Test fun unicodeLimitsPreserveCompleteCodepoints() {
        val message = "\uD83D\uDE42".repeat(600)
        val preview = admit(owner(), candidate().copy(sender = message, text = message))!!
        assertEquals(80, preview.sender.codePointCount(0, preview.sender.length))
        assertEquals(512, preview.text.codePointCount(0, preview.text.length))
        assertTrue(Character.isLowSurrogate(preview.text.last()))
    }

    @Test fun emptyAndGroupSummaryNotificationsNeverCreateCards() {
        assertNull(admit(owner(), candidate().copy(sender = " ")))
        assertNull(admit(owner(), candidate().copy(text = " ")))
        assertNull(admit(owner(), candidate().copy(sourceKey = "")))
        assertNull(admit(owner(), candidate().copy(sourceKey = "x".repeat(2049))))
        assertNull(admit(owner(), candidate().copy(groupSummary = true)))
    }

    @Test fun elapsedAndWallDriftCannotReopenExpiredReplayWindow() {
        val admission = owner()
        assertNotNull(admit(admission))
        assertNull(admit(admission, candidate(), now = wall + 2_000, tick = elapsed + 32_000))
        assertNull(admit(admission, candidate(at = wall + 32_000), now = wall + 32_000, tick = elapsed + 2_000))
        assertNotNull(admit(admission, candidate(key = "fresh", at = wall + 32_000), now = wall + 32_000, tick = elapsed + 32_000))
    }

    @Test fun backwardsClocksFailClosed() {
        assertNull(admit(owner(), now = wall - 1))
        assertNull(admit(owner(), tick = elapsed - 1))
    }
}