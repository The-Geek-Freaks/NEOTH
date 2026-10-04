import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate {
  private let deepLinkChannel = "neoth_companion/deep_link"
  private var initialPairLink: String?
  private var channel: FlutterMethodChannel?

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    initialPairLink = pairLink(launchOptions?[.url] as? URL)
    GeneratedPluginRegistrant.register(with: self)
    let finished = super.application(application, didFinishLaunchingWithOptions: launchOptions)
    installChannelIfReady()
    return finished
  }

  private func installChannelIfReady() {
    guard let controller = window?.rootViewController as? FlutterViewController else { return }
    channel = FlutterMethodChannel(name: deepLinkChannel, binaryMessenger: controller.binaryMessenger)
    channel?.setMethodCallHandler { [weak self] call, result in
      if call.method == "initialPairLink" { result(self?.initialPairLink) } else { result(FlutterMethodNotImplemented) }
    }
  }

  override func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    if let pair = pairLink(url) { channel?.invokeMethod("pairLink", arguments: pair); return true }
    return super.application(app, open: url, options: options)
  }

  private func pairLink(_ url: URL?) -> String? {
    guard let url, url.scheme == "neoth", url.host == "companion", url.path == "/pair" else { return nil }
    return url.absoluteString
  }
}
