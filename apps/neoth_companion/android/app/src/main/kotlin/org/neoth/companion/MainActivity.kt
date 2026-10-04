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

    override fun onCreate(savedInstanceState: Bundle?) {
        initialPairLink = pairLink(intent)
        super.onCreate(savedInstanceState)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
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

    private fun pairLink(intent: Intent?): String? {
        val uri = intent?.data ?: return null
        return if (uri.scheme == "neoth" && uri.host == "companion" && uri.path == "/pair") uri.toString() else null
    }
}
