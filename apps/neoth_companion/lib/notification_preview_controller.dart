import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

const previewPackages = <String, String>{
  'com.whatsapp': 'WhatsApp',
  'com.whatsapp.w4b': 'WhatsApp Business',
  'org.telegram.messenger': 'Telegram',
};

class IncomingNotificationPreview {
  const IncomingNotificationPreview({required this.source, required this.channel,
    required this.sender, required this.text, required this.expiresAt});
  final String source;
  final String channel;
  final String sender;
  final String text;
  final DateTime expiresAt;
}

/// Local display only. There is no chat, provider, or send dependency.
class NotificationPreviewController extends ChangeNotifier {
  NotificationPreviewController({MethodChannel? channel, bool? supported,
    DateTime Function()? now})
      : _channel = channel ?? const MethodChannel('neoth_companion/notification_preview'),
        supported = supported ?? (!kIsWeb && defaultTargetPlatform == TargetPlatform.android),
        _now = now ?? DateTime.now,
        _owner = ++_owners {
    if (this.supported) _channel.setMethodCallHandler(_platformEvent);
  }

  static int _owners = 0;
  final int _owner;
  final MethodChannel _channel;
  final DateTime Function() _now;
  final bool supported;
  int _epoch = 0;
  String _scope = '';
  bool _disposed = false;
  bool _visible = false;
  bool enabled = false;
  bool systemAccess = false;
  bool quietHours = false;
  int quietStart = 22 * 60;
  int quietEnd = 7 * 60;
  Set<String> _packages = {};
  Set<String> get packages => Set.unmodifiable(_packages);
  IncomingNotificationPreview? current;
  String? error;
  Timer? _expiry;
  final Map<String, DateTime> _seen = {};

  bool get active => supported && enabled && _visible && systemAccess && !_disposed;

  bool _quietAt(DateTime now) {
    if (!quietHours) return false;
    final minute = now.hour * 60 + now.minute;
    if (quietStart == quietEnd) return true;
    return quietStart < quietEnd
        ? minute >= quietStart && minute < quietEnd
        : minute >= quietStart || minute < quietEnd;
  }

  Future<void> setVisible(bool visible) async {
    if (_disposed) return;
    _visible = visible;
    await _configure();
  }

  Future<void> setEnabled(bool value) async {
    if (_disposed) return;
    enabled = value && supported;
    await _configure();
  }

  Future<void> setPackage(String package, bool value) async {
    if (_disposed || !previewPackages.containsKey(package)) return;
    _packages = {..._packages};
    if (value) { _packages.add(package); } else { _packages.remove(package); }
    await _configure();
  }

  Future<void> setQuietHours({required bool enabled, required int start, required int end}) async {
    if (_disposed || start < 0 || start >= 1440 || end < 0 || end >= 1440) return;
    quietHours = enabled;
    quietStart = start;
    quietEnd = end;
    await _configure();
  }

  void _clear() {
    _expiry?.cancel();
    _expiry = null;
    current = null;
  }

  Future<void> _configure() async {
    final epoch = ++_epoch;
    _scope = 'preview_${_owner}_$epoch';
    _clear();
    systemAccess = false;
    error = null;
    notifyListeners();
    if (!supported) return;
    try {
      final response = await _channel.invokeMapMethod<String, dynamic>('configure', {
        'scope': _scope, 'enabled': enabled && _visible, 'packages': _packages.toList()..sort(),
        'quiet': quietHours, 'quietStart': quietStart, 'quietEnd': quietEnd,
      });
      if (_disposed || epoch != _epoch) return;
      if (response == null || response['scope'] != _scope || response['access'] is! bool) {
        throw const FormatException('Invalid preview admission');
      }
      systemAccess = response['access'] as bool;
    } on PlatformException {
      if (_disposed || epoch != _epoch) return;
      error = 'Notification previews are unavailable.';
    } on MissingPluginException {
      if (_disposed || epoch != _epoch) return;
      error = 'Notification previews are unavailable.';
    } on TypeError {
      if (_disposed || epoch != _epoch) return;
      error = 'Notification previews are unavailable.';
    } on FormatException {
      if (_disposed || epoch != _epoch) return;
      error = 'Notification previews are unavailable.';
    }
    if (!_disposed && epoch == _epoch) notifyListeners();
  }

  Future<void> openSystemSettings() async {
    if (!supported || !_visible || _disposed) return;
    try {
      await _channel.invokeMethod<void>('openSettings');
    } on PlatformException {
      if (!_disposed) { error = 'Notification access settings are unavailable.'; notifyListeners(); }
    } on MissingPluginException {
      if (!_disposed) { error = 'Notification access settings are unavailable.'; notifyListeners(); }
    }
  }

  Future<void> _platformEvent(MethodCall call) async {
    if (_disposed || call.arguments is! Map) return;
    final value = call.arguments as Map;
    if (value['scope'] != _scope) return;
    if (call.method == 'revoked') {
      await setEnabled(false);
      return;
    }
    if (call.method != 'preview' || !active || value.length != 8) return;
    final now = _now();
    if (_quietAt(now)) { _clear(); notifyListeners(); return; }
    final source = value['source'];
    final package = value['package'];
    final sender = value['sender'];
    final text = value['text'];
    final posted = value['postedAt'];
    final expires = value['expiresAt'];
    if (source is! String || !RegExp(r'^[a-f0-9]{64}$').hasMatch(source) ||
        package is! String || !_packages.contains(package) || value['channel'] != previewPackages[package] ||
        sender is! String || sender.isEmpty || sender.length > 160 || sender.runes.length > 80 ||
        text is! String || text.isEmpty || text.length > 1024 || text.runes.length > 512 ||
        posted is! int || expires is! int || posted <= 0 || posted > now.millisecondsSinceEpoch ||
        expires <= now.millisecondsSinceEpoch || expires - posted != 30000) return;
    final deadline = DateTime.fromMillisecondsSinceEpoch(expires);
    _seen.removeWhere((_, expiry) => !expiry.isAfter(now));
    if (_seen.containsKey(source) || _seen.length >= 128) return;
    _seen[source] = deadline;
    _clear();
    current = IncomingNotificationPreview(source: source, channel: previewPackages[package]!,
      sender: sender, text: text, expiresAt: deadline);
    var lifetime = deadline.difference(now);
    if (quietHours) {
      var quiet = DateTime(now.year, now.month, now.day, quietStart ~/ 60, quietStart % 60);
      if (!quiet.isAfter(now)) quiet = DateTime(now.year, now.month, now.day + 1, quietStart ~/ 60, quietStart % 60);
      final untilQuiet = quiet.difference(now);
      if (untilQuiet < lifetime) lifetime = untilQuiet;
    }
    _expiry = Timer(lifetime, () {
      if (_disposed) return;
      _clear();
      notifyListeners();
    });
    notifyListeners();
  }

  void dismiss() {
    if (_disposed) return;
    _clear();
    notifyListeners();
  }

  @override
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _clear();
    _seen.clear();
    ++_epoch;
    if (supported) {
      _channel.setMethodCallHandler(null);
      unawaited(_channel.invokeMethod<void>('configure', {
        'scope': 'preview_${_owner}_$_epoch', 'enabled': false, 'packages': <String>[],
        'quiet': false, 'quietStart': 0, 'quietEnd': 0,
      }).catchError((Object _) {}));
    }
    super.dispose();
  }
}