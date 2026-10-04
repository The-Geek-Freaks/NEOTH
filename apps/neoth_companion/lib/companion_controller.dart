import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';

import 'models.dart';
import 'native_bridge.dart';
import 'secure_store.dart';

typedef NativeBridgeFactory = NativeBridge Function(Uint8List secret);

/// Keeps pairing authority explicit: success is persisted exactly once, while
/// denied/revoked responses retain the old identity and never trigger re-pair.
class CompanionController extends ChangeNotifier {
  CompanionController({required CompanionStore store, required NativeBridgeFactory bridgeFactory})
      : _store = store,
        _bridgeFactory = bridgeFactory;

  final CompanionStore _store;
  final NativeBridgeFactory _bridgeFactory;
  NativeBridge? _bridge;
  EnrollmentAccepted? _enrollment;
  CompanionStatus? status;
  CompanionViewState state = CompanionViewState.unpaired;
  bool _disposed = false;

  Future<void> restore() async {
    _enrollment = await _store.loadEnrollment();
    if (_enrollment == null) {
      _set(CompanionViewState.unpaired);
      return;
    }
    _set(CompanionViewState.offline);
  }

  Future<void> pair(String rawInvite, String label) async {
    if (_disposed || state == CompanionViewState.pairing) return;
    // A retained active enrollment must be deliberately cleared by the person
    // holding the device; a pasted invite cannot silently replace it.
    if (_enrollment != null) {
      _set(CompanionViewState.failed);
      return;
    }
    _set(CompanionViewState.pairing);
    try {
      final result = await _ensureBridge().pair(rawInvite.trim(), label.trim());
      if (result.kind == NativeOperationResult.ok && result.publicJson != null) {
        final accepted = EnrollmentAccepted.fromBridgeJson(result.publicJson!);
        await _store.saveEnrollment(accepted); // durable only after actual success
        _enrollment = accepted;
        _set(CompanionViewState.offline);
      } else {
        _setForResult(result);
      }
    } on FormatException {
      _set(CompanionViewState.failed);
    } on StateError {
      _set(CompanionViewState.failed);
    }
  }

  Future<void> refresh() async {
    if (_disposed || state == CompanionViewState.pairing) return;
    final enrollment = _enrollment;
    if (enrollment == null) {
      _set(CompanionViewState.unpaired);
      return;
    }
    _set(CompanionViewState.pairing);
    try {
      final result = await _ensureBridge().reconnect(jsonEncode(enrollment.reconnectDescriptor), enrollment.deviceId);
      if (result.kind == NativeOperationResult.ok && result.publicJson != null) {
        final snapshot = CompanionStatus.fromBridgeJson(result.publicJson!);
        if (snapshot.deviceId != enrollment.deviceId) throw const FormatException('cross-device status');
        status = snapshot;
        _set(CompanionViewState.ready);
      } else {
        _setForResult(result);
      }
    } on FormatException {
      _set(CompanionViewState.failed);
    } on StateError {
      _set(CompanionViewState.offline);
    }
  }

  Future<void> forgetLocalEnrollment() async {
    if (_disposed) return;
    await _store.clearEnrollment();
    _enrollment = null;
    status = null;
    _set(CompanionViewState.unpaired);
  }

  NativeBridge _ensureBridge() => _bridge ?? (throw StateError('protected device identity is not ready'));

  Future<void> prepareBridge() async {
    if (_disposed || _bridge != null) return;
    final secret = await _store.loadOrCreateDeviceSecret();
    try {
      _bridge = _bridgeFactory(secret);
    } finally {
      secret.fillRange(0, secret.length, 0);
    }
  }

  void _setForResult(NativeBridgeResult result) {
    final code = result.publicJson?['body'] is Map<String, Object?>
        ? (result.publicJson!['body']! as Map<String, Object?>)['code']
        : null;
    if (result.kind == NativeOperationResult.denied) {
      _set(code == 'revoked' ? CompanionViewState.revoked : CompanionViewState.denied);
    } else if (result.kind == NativeOperationResult.cancelled) {
      _set(CompanionViewState.offline);
    } else {
      _set(CompanionViewState.offline);
    }
  }

  void _set(CompanionViewState next) {
    if (_disposed) return;
    state = next;
    notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    final bridge = _bridge;
    _bridge = null;
    if (bridge != null) {
      // The FFI owner cancels, reaches the terminal operation state, frees the
      // operation, and only then releases the native bridge allocation.
      unawaited(bridge.dispose());
    }
    super.dispose();
  }
}
