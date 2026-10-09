package org.neoth.companion

import android.content.Intent
import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    private val channelName = "neoth_companion/deep_link"
    private var channel: MethodChannel? = null
    private var initialPairLink: String? = null
    private var notificationPreview: NotificationPreviewOwner? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        initialPairLink = pairLink(intent)
        super.onCreate(savedInstanceState)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        notificationPreview = NotificationPreviewOwner(this, flutterEngine.dartExecutor.binaryMessenger)
        channel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName).also { bridge ->
            bridge.setMethodCallHandler { call, result ->
                if (call.method == "initialPairLink") result.success(initialPairLink) else result.notImplemented()
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        pairLink(intent)?.let { channel?.invokeMethod("pairLink", it) }
    }

    override fun onResume() {
        super.onResume()
        notificationPreview?.setForeground(true)
    }

    override fun onPause() {
        notificationPreview?.setForeground(false)
        super.onPause()
    }

    override fun onDestroy() {
        notificationPreview?.close()
        notificationPreview = null
        super.onDestroy()
    }

    private fun pairLink(intent: Intent?): String? {
        val uri = intent?.data ?: return null
        return if (uri.scheme == "neoth" && uri.host == "companion" && uri.path == "/pair") uri.toString() else null
    }
}
