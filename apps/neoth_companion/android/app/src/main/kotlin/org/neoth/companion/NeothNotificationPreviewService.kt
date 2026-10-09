package org.neoth.companion

import android.app.KeyguardManager
import android.app.Notification
import android.app.NotificationManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.Settings
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import io.flutter.embedding.android.FlutterActivity
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodChannel
import java.util.Calendar
import java.util.concurrent.atomic.AtomicBoolean

internal object NotificationPreviewHub {
    @Volatile var owner: NotificationPreviewOwner? = null
}

/** Foreground-only local preview; no native channel or remote chat authority. */
internal class NotificationPreviewOwner(
    private val activity: FlutterActivity,
    messenger: BinaryMessenger,
) {
    private val channel = MethodChannel(messenger, "neoth_companion/notification_preview")
    private val admission = NotificationPreviewAdmission()
    private var foreground = false
    private var scope: String? = null
    private var closed = false

    init {
        NotificationPreviewHub.owner?.close()
        NotificationPreviewHub.owner = this
        channel.setMethodCallHandler { call, result ->
            when (call.method) {
                "configure" -> {
                    val arguments = call.arguments as? Map<*, *>
                    val nextScope = arguments?.get("scope") as? String
                    val enabled = arguments?.get("enabled") as? Boolean
                    val packages = arguments?.get("packages") as? List<*>
                    val quiet = arguments?.get("quiet") as? Boolean
                    val start = arguments?.get("quietStart") as? Int
                    val end = arguments?.get("quietEnd") as? Int
                    if (closed || nextScope == null || !nextScope.matches(Regex("[A-Za-z0-9_-]{1,64}")) ||
                        enabled == null || packages == null || packages.size > 3 ||
                        packages.any { it !is String || it !in previewPackages } ||
                        packages.distinct().size != packages.size || quiet == null ||
                        start == null || start !in 0..1439 || end == null || end !in 0..1439) {
                        admission.suspend()
                        scope = null
                        result.error("invalid_preview_settings", "Preview settings are invalid.", null)
                    } else {
                        val access = hasSystemAccess()
                        scope = nextScope
                        admission.configure(
                            PreviewPolicy(enabled && foreground && access, packages.filterIsInstance<String>().toSet(), quiet, start, end),
                            nextScope, System.currentTimeMillis(), SystemClock.elapsedRealtime(),
                        )
                        result.success(mapOf("scope" to nextScope, "access" to access))
                    }
                }
                "openSettings" -> {
                    if (!closed && foreground) {
                        try {
                            activity.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                            result.success(null)
                        } catch (_: android.content.ActivityNotFoundException) {
                            result.error("settings_unavailable", "Notification access settings are unavailable.", null)
                        }
                    } else result.error("not_visible", "Open NEOTH before changing notification access.", null)
                }
                else -> result.notImplemented()
            }
        }
    }

    fun setForeground(value: Boolean) {
        foreground = value && !closed
        if (!foreground) admission.suspend()
    }

    fun systemDisconnected() {
        admission.suspend()
        scope?.let { channel.invokeMethod("revoked", mapOf("scope" to it)) }
    }

    private fun hasSystemAccess(): Boolean {
        val component = ComponentName(activity, NeothNotificationPreviewService::class.java)
        if (Build.VERSION.SDK_INT >= 27) {
            return activity.getSystemService(NotificationManager::class.java).isNotificationListenerAccessGranted(component)
        }
        val enabled = Settings.Secure.getString(activity.contentResolver, "enabled_notification_listeners") ?: return false
        return enabled.split(':').any { ComponentName.unflattenFromString(it) == component }
    }

    fun posted(notification: StatusBarNotification) {
        if (closed || !foreground || !admission.admitsPackage(notification.packageName)) return
        val unlocked = !activity.getSystemService(KeyguardManager::class.java).isKeyguardLocked
        if (!unlocked || !hasSystemAccess()) return
        val value = notification.notification
        if ((value.flags and Notification.FLAG_GROUP_SUMMARY) != 0) return
        val extras = value.extras ?: return
        val sender = boundedPreviewText(extras.getCharSequence(Notification.EXTRA_TITLE), 80) ?: return
        val text = boundedPreviewText(extras.getCharSequence(Notification.EXTRA_BIG_TEXT)
            ?: extras.getCharSequence(Notification.EXTRA_TEXT), 512) ?: return
        val clock = Calendar.getInstance()
        val preview = admission.admit(
            PreviewCandidate(notification.packageName, notification.key, notification.postTime, sender, text),
            System.currentTimeMillis(), SystemClock.elapsedRealtime(),
            clock.get(Calendar.HOUR_OF_DAY) * 60 + clock.get(Calendar.MINUTE),
            systemAccess = true, foreground = foreground, unlocked = unlocked,
        ) ?: return
        if (SystemClock.elapsedRealtime() >= preview.expiresElapsed) return
        channel.invokeMethod("preview", mapOf(
            "scope" to preview.scope, "source" to preview.source, "package" to preview.packageName,
            "channel" to preview.channel, "sender" to preview.sender, "text" to preview.text,
            "postedAt" to preview.postedAt, "expiresAt" to preview.expiresAt,
        ))
    }

    fun close() {
        if (closed) return
        closed = true
        foreground = false
        admission.suspend()
        scope = null
        channel.setMethodCallHandler(null)
        if (NotificationPreviewHub.owner === this) NotificationPreviewHub.owner = null
    }
}

class NeothNotificationPreviewService : NotificationListenerService() {
    private val main = Handler(Looper.getMainLooper())
    private val pending = AtomicBoolean(false)

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null || NotificationPreviewHub.owner == null || sbn.packageName !in previewPackages) return
        // Android 23 may call from another thread. Bound pending work to one event.
        if (!pending.compareAndSet(false, true)) return
        val operation = Runnable {
            try { NotificationPreviewHub.owner?.posted(sbn) } finally { pending.set(false) }
        }
        if (Looper.myLooper() == Looper.getMainLooper()) operation.run()
        else if (!main.post(operation)) pending.set(false)
    }

    override fun onListenerDisconnected() {
        main.post { NotificationPreviewHub.owner?.systemDisconnected() }
    }
}