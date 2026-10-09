package org.neoth.companion

import java.security.MessageDigest

internal val previewPackages = mapOf(
    "com.whatsapp" to "WhatsApp",
    "com.whatsapp.w4b" to "WhatsApp Business",
    "org.telegram.messenger" to "Telegram",
)

internal data class PreviewPolicy(
    val enabled: Boolean = false,
    val packages: Set<String> = emptySet(),
    val quietHours: Boolean = false,
    val quietStart: Int = 22 * 60,
    val quietEnd: Int = 7 * 60,
) {
    init {
        require(packages.all { it in previewPackages })
        require(quietStart in 0..1439 && quietEnd in 0..1439)
    }

    fun isQuiet(minute: Int): Boolean {
        if (minute !in 0..1439) return true
        if (!quietHours) return false
        if (quietStart == quietEnd) return true
        return if (quietStart < quietEnd) minute >= quietStart && minute < quietEnd
        else minute >= quietStart || minute < quietEnd
    }
}

internal data class PreviewCandidate(
    val packageName: String,
    val sourceKey: String,
    val postedAt: Long,
    val sender: String,
    val text: String,
    val groupSummary: Boolean = false,
)

// No notification action, pending intent, channel address, or reply authority.
internal data class AdmittedPreview(
    val scope: String,
    val source: String,
    val packageName: String,
    val channel: String,
    val sender: String,
    val text: String,
    val postedAt: Long,
    val expiresAt: Long,
    val expiresElapsed: Long,
)

/** Single main-thread owner, fed only by current onNotificationPosted events. */
internal class NotificationPreviewAdmission {
    private var policy = PreviewPolicy()
    private var scope: String? = null
    private var beganWall = 0L
    private var beganElapsed = 0L
    // Live identities are never evicted to admit more traffic. Overflow drops.
    private val seen = linkedMapOf<String, Long>()

    fun configure(next: PreviewPolicy, nextScope: String, wall: Long, elapsed: Long) {
        require(nextScope.matches(Regex("[A-Za-z0-9_-]{1,64}")))
        require(wall > 0 && elapsed >= 0)
        policy = next
        scope = nextScope
        beganWall = wall
        beganElapsed = elapsed
    }

    fun suspend() {
        policy = PreviewPolicy()
        scope = null
    }

    fun admitsPackage(packageName: String): Boolean =
        scope != null && policy.enabled && packageName in policy.packages

    fun admit(
        candidate: PreviewCandidate,
        wall: Long,
        elapsed: Long,
        minute: Int,
        systemAccess: Boolean,
        foreground: Boolean,
        unlocked: Boolean,
    ): AdmittedPreview? {
        val activeScope = scope ?: return null
        if (!policy.enabled || !systemAccess || !foreground || !unlocked || policy.isQuiet(minute)) return null
        if (candidate.packageName !in policy.packages || candidate.groupSummary) return null
        val channel = previewPackages[candidate.packageName] ?: return null
        if (wall < beganWall || elapsed < beganElapsed || candidate.postedAt < beganWall) return null
        // Wall-clock changes must not reopen an expired monotonic replay window.
        // The small tolerance covers the two separate clock reads, not a new TTL.
        if (kotlin.math.abs((wall - beganWall) - (elapsed - beganElapsed)) > 2_000L) return null
        if (candidate.postedAt > wall || candidate.postedAt <= 0) return null
        val age = wall - candidate.postedAt
        if (age >= 30_000L) return null
        if (candidate.sourceKey.isBlank() || candidate.sourceKey.length > 2048) return null
        val sender = boundedPreviewText(candidate.sender, 80) ?: return null
        val text = boundedPreviewText(candidate.text, 512) ?: return null
        val digest = MessageDigest.getInstance("SHA-256")
        for (part in listOf(candidate.packageName, candidate.sourceKey, candidate.postedAt.toString())) {
            val bytes = part.toByteArray(Charsets.UTF_8)
            digest.update(bytes.size.toString().toByteArray(Charsets.US_ASCII))
            digest.update(0.toByte())
            digest.update(bytes)
        }
        val source = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
        seen.entries.removeAll { it.value <= elapsed }
        if (source in seen || seen.size >= 128) return null
        val remaining = 30_000L - age
        if (wall > Long.MAX_VALUE - remaining || elapsed > Long.MAX_VALUE - remaining) return null
        val deadline = elapsed + remaining
        seen[source] = deadline
        return AdmittedPreview(activeScope, source, candidate.packageName, channel, sender, text,
            candidate.postedAt, wall + remaining, deadline)
    }
}

internal fun boundedPreviewText(value: CharSequence?, maximum: Int): String? {
    if (value == null || value.isEmpty()) return null
    // Bound the copy before converting arbitrary Android CharSequences.
    val copied = value.subSequence(0, minOf(value.length, maximum * 2)).toString().trim()
    if (copied.isEmpty()) return null
    val codepoints = copied.codePointCount(0, copied.length)
    val end = copied.offsetByCodePoints(0, minOf(maximum, codepoints))
    val bounded = copied.substring(0, end)
    // A copied boundary cannot leave half of a UTF-16 surrogate pair.
    return bounded.trimEnd { Character.isHighSurrogate(it) }.takeIf { it.isNotBlank() }
}