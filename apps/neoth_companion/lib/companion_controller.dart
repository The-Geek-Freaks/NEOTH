import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';

import 'bridge_input.dart';
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
  CompanionChatTerminal? chatTerminal;
  String? chatLocalMessage;
  bool chatPending = false;
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

  bool get canSendChat => _enrollment?.grantedScope == companionChatSendScope;
  bool get canRefreshStatus => _enrollment?.grantedScope == companionStatusReadScope;
  String? get grantedScope => _enrollment?.grantedScope;

  /// Starts exactly one ordinary text turn. A local validation error is known
  /// before the bridge worker starts; every remote terminal is rendered from
  /// its typed public outcome and is never retried here.
  Future<void> sendChat(String message) async {
    if (_disposed || chatPending) return;
    final enrollment = _enrollment;
    if (enrollment == null || !canSendChat) {
      chatLocalMessage = 'This phone does not have chat permission. Pair again with a chat invite.';
      _notify();
      return;
    }
    try {
      validateOrdinaryChatMessage(message);
    } on FormatException {
      chatLocalMessage = 'Enter one ordinary message of at most 640 UTF-8 bytes. Slash actions are unavailable.';
      _notify();
      return;
    }
    chatPending = true;
    chatTerminal = null;
    chatLocalMessage = null;
    _notify();
    try {
      final result = await _ensureBridge().chat(jsonEncode(enrollment.reconnectDescriptor), enrollment.deviceId, message);
      if (result.publicJson != null) {
        chatTerminal = CompanionChatTerminal.fromBridgeJson(result.publicJson!);
      } else if (result.kind == NativeOperationResult.cancelled) {
        chatLocalMessage = 'The phone disconnected before a terminal chat response was confirmed.';
      } else {
        chatLocalMessage = 'Chat could not be started. No message is retried automatically.';
      }
    } on FormatException {
      chatLocalMessage = 'The chat response could not be verified.';
    } on StateError {
      chatLocalMessage = 'NEOTH is unavailable. No message is retried automatically.';
    } finally {
      chatPending = false;
      _notify();
    }
  }

  Future<void> forgetLocalEnrollment() async {
    if (_disposed) return;
    await _store.clearEnrollment();
    _enrollment = null;
    status = null;
    chatTerminal = null;
    chatLocalMessage = null;
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
    final code = result.publicJson?['code'];
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

  void _notify() {
    if (!_disposed) notifyListeners();
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
