import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bridge_input.dart';
import 'models.dart';

enum NativeOperationResult { pending, ok, denied, failed, cancelled }

class NativeBridgeResult {
  const NativeBridgeResult(this.kind, [this.publicJson]);
  final NativeOperationResult kind;
  final Map<String, Object?>? publicJson;
}

abstract interface class NativeBridge {
  Future<NativeBridgeResult> pair(String inviteUrl, String label);
  Future<NativeBridgeResult> reconnect(String descriptorJson, String deviceId);
  Future<NativeBridgeResult> chat(String descriptorJson, String deviceId, String message);
  /// Signals only the existing in-flight operation. The poll owner retains
  /// responsibility for observing its terminal result and freeing its handle.
  Future<void> cancelActiveChat();
  Future<void> dispose();
}

abstract interface class NativeBridgeWithActivity implements NativeBridge {
  Future<NativeBridgeResult> chatWithActivity(String descriptorJson, String deviceId, String message, void Function(CompanionChatActivitySnapshot) onActivity);
}

abstract interface class NativeBridgeWithStream implements NativeBridgeWithActivity {
  Future<NativeBridgeResult> chatWithStream(String descriptorJson, String deviceId, String message,
      void Function(CompanionChatActivitySnapshot) onActivity, void Function(CompanionChatStreamSnapshot) onStream);
}

final class _Bridge extends Opaque {}
final class _Operation extends Opaque {}

typedef _BridgeNewNative = Pointer<_Bridge> Function(Pointer<Uint8>, IntPtr);
typedef _BridgeNewDart = Pointer<_Bridge> Function(Pointer<Uint8>, int);
typedef _BridgeFreeNative = Void Function(Pointer<_Bridge>);
typedef _BridgeFreeDart = void Function(Pointer<_Bridge>);
typedef _PairStartNative = Pointer<_Operation> Function(Pointer<_Bridge>, Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr);
typedef _PairStartDart = Pointer<_Operation> Function(Pointer<_Bridge>, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _ReconnectStartNative = Pointer<_Operation> Function(Pointer<_Bridge>, Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr);
typedef _ReconnectStartDart = Pointer<_Operation> Function(Pointer<_Bridge>, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _ChatStartNative = Pointer<_Operation> Function(Pointer<_Bridge>, Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr);
typedef _ChatStartDart = Pointer<_Operation> Function(Pointer<_Bridge>, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _ChatStartV2Native = Pointer<_Operation> Function(Pointer<_Bridge>, Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Uint8);
typedef _ChatStartV2Dart = Pointer<_Operation> Function(Pointer<_Bridge>, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, int);
typedef _PollNative = Int32 Function(Pointer<_Operation>, Pointer<Uint8>, IntPtr, Pointer<IntPtr>);
typedef _PollDart = int Function(Pointer<_Operation>, Pointer<Uint8>, int, Pointer<IntPtr>);
typedef _PollV2Native = Int32 Function(Pointer<_Operation>, Pointer<Uint8>, IntPtr, Pointer<IntPtr>);
typedef _PollV2Dart = int Function(Pointer<_Operation>, Pointer<Uint8>, int, Pointer<IntPtr>);
typedef _OperationVoidNative = Void Function(Pointer<_Operation>);
typedef _OperationVoidDart = void Function(Pointer<_Operation>);

/// Owns one Rust bridge allocation and exactly one in-flight operation.  The
/// opaque native bridge derives the signing and Noise identities from the
/// protected seed; neither private material nor invite data crosses back.
class FfiNativeBridge implements NativeBridgeWithStream {
  FfiNativeBridge._(DynamicLibrary library, Uint8List seed)
      : _bridgeFree = library.lookupFunction<_BridgeFreeNative, _BridgeFreeDart>('neoth_companion_bridge_free'),
        _pairStart = library.lookupFunction<_PairStartNative, _PairStartDart>('neoth_companion_pair_start'),
        _reconnectStart = library.lookupFunction<_ReconnectStartNative, _ReconnectStartDart>('neoth_companion_reconnect_start'),
        _chatStart = library.lookupFunction<_ChatStartNative, _ChatStartDart>('neoth_companion_chat_start'),
        _chatStartV2 = _lookupChatStartV2(library),
        _chatStartV3 = _lookupChatStartV3(library),
        _poll = library.lookupFunction<_PollNative, _PollDart>('neoth_companion_operation_poll'),
        _pollV2 = _lookupPollV2(library),
        _pollV3 = _lookupPollV3(library),
        _operationCancel = library.lookupFunction<_OperationVoidNative, _OperationVoidDart>('neoth_companion_operation_cancel'),
        _operationFree = library.lookupFunction<_OperationVoidNative, _OperationVoidDart>('neoth_companion_operation_free'),
        _bridge = _create(library.lookupFunction<_BridgeNewNative, _BridgeNewDart>('neoth_companion_bridge_new'), seed);

  factory FfiNativeBridge.fromProtectedSeed(Uint8List seed) {
    if (seed.length != 32) throw ArgumentError.value(seed.length, 'seed.length');
    final library = Platform.isAndroid
        ? DynamicLibrary.open('libneoth_companion_bridge.so')
        : DynamicLibrary.process();
    return FfiNativeBridge._(library, seed);
  }

  final _BridgeFreeDart _bridgeFree;
  final _PairStartDart _pairStart;
  final _ReconnectStartDart _reconnectStart;
  final _ChatStartDart _chatStart;
  final _ChatStartV2Dart? _chatStartV2;
  final _ChatStartV2Dart? _chatStartV3;
  final _PollDart _poll;
  final _PollV2Dart? _pollV2;
  final _PollV2Dart? _pollV3;
  final _OperationVoidDart _operationCancel;
  final _OperationVoidDart _operationFree;
  Pointer<_Bridge> _bridge;
  Pointer<_Operation>? _active;
  Completer<void>? _activeFinished;
  Future<void>? _disposeFuture;
  bool _closing = false;
  bool _activeCancelRequested = false;

  static Pointer<_Bridge> _create(_BridgeNewDart newBridge, Uint8List secret) {
    final native = calloc<Uint8>(32);
    try {
      native.asTypedList(32).setAll(0, secret);
      final bridge = newBridge(native, 32);
      if (bridge == nullptr) throw StateError('companion bridge unavailable');
      return bridge;
    } finally {
      native.asTypedList(32).fillRange(0, 32, 0);
      calloc.free(native);
      secret.fillRange(0, secret.length, 0);
    }
  }

  @override
  Future<NativeBridgeResult> pair(String inviteUrl, String label) {
    validateInvite(inviteUrl);
    validateLabel(label);
    return _start((url, urlLength, deviceLabel, labelLength) => _pairStart(_bridge, url, urlLength, deviceLabel, labelLength), inviteUrl, label);
  }

  @override
  Future<NativeBridgeResult> reconnect(String descriptorJson, String deviceId) {
    if (!isBoundedReconnectInput(descriptorJson, deviceId)) {
      return Future.value(const NativeBridgeResult(NativeOperationResult.failed));
    }
    return _start((descriptor, descriptorLength, id, idLength) => _reconnectStart(_bridge, descriptor, descriptorLength, id, idLength), descriptorJson, deviceId);
  }

  @override
  Future<NativeBridgeResult> chat(String descriptorJson, String deviceId, String message) {
    if (!isBoundedReconnectInput(descriptorJson, deviceId)) {
      return Future.value(const NativeBridgeResult(NativeOperationResult.failed));
    }
    validateOrdinaryChatMessage(message);
    return _startThree(
      (descriptor, descriptorLength, id, idLength, text, textLength) =>
          _chatStart(_bridge, descriptor, descriptorLength, id, idLength, text, textLength),
      descriptorJson,
      deviceId,
      message,
    );
  }

  @override
  Future<NativeBridgeResult> chatWithActivity(String descriptorJson, String deviceId, String message, void Function(CompanionChatActivitySnapshot) onActivity) {
    final start = _chatStartV2; final poll = _pollV2;
    if (start == null || poll == null) return chat(descriptorJson, deviceId, message);
    if (!isBoundedReconnectInput(descriptorJson, deviceId)) return Future.value(const NativeBridgeResult(NativeOperationResult.failed));
    validateOrdinaryChatMessage(message);
    return _startThree((descriptor, descriptorLength, id, idLength, text, textLength) => start(_bridge, descriptor, descriptorLength, id, idLength, text, textLength, 1), descriptorJson, deviceId, message, poll: poll, onActivity: onActivity);
  }

  @override
  Future<NativeBridgeResult> chatWithStream(String descriptorJson, String deviceId, String message,
      void Function(CompanionChatActivitySnapshot) onActivity, void Function(CompanionChatStreamSnapshot) onStream) {
    final start = _chatStartV3; final poll = _pollV3;
    if (start == null || poll == null) return chatWithActivity(descriptorJson, deviceId, message, onActivity);
    if (!isBoundedReconnectInput(descriptorJson, deviceId)) return Future.value(const NativeBridgeResult(NativeOperationResult.failed));
    validateOrdinaryChatMessage(message);
    return _startThree((descriptor, descriptorLength, id, idLength, text, textLength) =>
        start(_bridge, descriptor, descriptorLength, id, idLength, text, textLength, 1),
        descriptorJson, deviceId, message, poll: poll, onActivity: onActivity, onStream: onStream);
  }

  Future<NativeBridgeResult> _start(
      Pointer<_Operation> Function(Pointer<Uint8>, int, Pointer<Uint8>, int) invoke, String first, String second) async {
    _requireLive();
    if (_active != null) return const NativeBridgeResult(NativeOperationResult.failed);
    final firstBytes = utf8.encode(first);
    final secondBytes = utf8.encode(second);
    final firstNative = calloc<Uint8>(firstBytes.length);
    final secondNative = calloc<Uint8>(secondBytes.length);
    try {
      firstNative.asTypedList(firstBytes.length).setAll(0, firstBytes);
      secondNative.asTypedList(secondBytes.length).setAll(0, secondBytes);
      final operation = invoke(firstNative, firstBytes.length, secondNative, secondBytes.length);
      if (operation == nullptr) return const NativeBridgeResult(NativeOperationResult.failed);
      _active = operation;
      _activeCancelRequested = false;
      _activeFinished = Completer<void>();
      return await _pollUntilTerminal(operation);
    } finally {
      firstNative.asTypedList(firstBytes.length).fillRange(0, firstBytes.length, 0);
      secondNative.asTypedList(secondBytes.length).fillRange(0, secondBytes.length, 0);
      firstBytes.fillRange(0, firstBytes.length, 0);
      secondBytes.fillRange(0, secondBytes.length, 0);
      calloc.free(firstNative);
      calloc.free(secondNative);
    }
  }

  Future<NativeBridgeResult> _startThree(
      Pointer<_Operation> Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int) invoke,
      String first,
      String second,
      String third, {_PollDart? poll, void Function(CompanionChatActivitySnapshot)? onActivity, void Function(CompanionChatStreamSnapshot)? onStream}) async {
    _requireLive();
    if (_active != null) return const NativeBridgeResult(NativeOperationResult.failed);
    final firstBytes = utf8.encode(first);
    final secondBytes = utf8.encode(second);
    final thirdBytes = utf8.encode(third);
    final firstNative = calloc<Uint8>(firstBytes.length);
    final secondNative = calloc<Uint8>(secondBytes.length);
    final thirdNative = calloc<Uint8>(thirdBytes.length);
    try {
      firstNative.asTypedList(firstBytes.length).setAll(0, firstBytes);
      secondNative.asTypedList(secondBytes.length).setAll(0, secondBytes);
      thirdNative.asTypedList(thirdBytes.length).setAll(0, thirdBytes);
      final operation = invoke(firstNative, firstBytes.length, secondNative, secondBytes.length, thirdNative, thirdBytes.length);
      if (operation == nullptr) return const NativeBridgeResult(NativeOperationResult.failed);
      _active = operation;
      _activeCancelRequested = false;
      _activeFinished = Completer<void>();
      return await _pollUntilTerminal(operation, poll: poll, onActivity: onActivity, onStream: onStream);
    } finally {
      firstNative.asTypedList(firstBytes.length).fillRange(0, firstBytes.length, 0);
      secondNative.asTypedList(secondBytes.length).fillRange(0, secondBytes.length, 0);
      thirdNative.asTypedList(thirdBytes.length).fillRange(0, thirdBytes.length, 0);
      firstBytes.fillRange(0, firstBytes.length, 0);
      secondBytes.fillRange(0, secondBytes.length, 0);
      thirdBytes.fillRange(0, thirdBytes.length, 0);
      calloc.free(firstNative);
      calloc.free(secondNative);
      calloc.free(thirdNative);
    }
  }

  Future<NativeBridgeResult> _pollUntilTerminal(Pointer<_Operation> operation, {_PollDart? poll, void Function(CompanionChatActivitySnapshot)? onActivity, void Function(CompanionChatStreamSnapshot)? onStream}) async {
    try {
      while (_active == operation) {
        final result = _readPoll(operation, poll ?? _poll, onActivity, onStream);
        if (result.kind != NativeOperationResult.pending) return result;
        await Future<void>.delayed(const Duration(milliseconds: 125));
      }
      return const NativeBridgeResult(NativeOperationResult.cancelled);
    } finally {
      if (_active == operation) _active = null;
      _activeCancelRequested = false;
      _operationFree(operation);
      _activeFinished?.complete();
      _activeFinished = null;
    }
  }

  NativeBridgeResult _readPoll(Pointer<_Operation> operation, _PollDart poll, void Function(CompanionChatActivitySnapshot)? onActivity, void Function(CompanionChatStreamSnapshot)? onStream) {
    final required = calloc<IntPtr>();
    try {
      final first = poll(operation, nullptr, 0, required);
      if (first == 0) return const NativeBridgeResult(NativeOperationResult.pending);
      // ABI r1 returned 1 for a probe whose buffer was absent; ABI r2 uses 5.
      // Both spellings are accepted only for this size-discovery call, so a
      // deployed r1 bridge cannot turn into a false terminal success.
      if ((first != 1 && first != 5) || required.value == 0 || required.value > 80 * 1024) {
        return NativeBridgeResult(_resultKind(first));
      }
      final outputLength = required.value;
      final output = calloc<Uint8>(outputLength + 1);
      try {
        final second = poll(operation, output, outputLength + 1, required);
        if (second == 0 || second == 5) return const NativeBridgeResult(NativeOperationResult.pending);
        final delivered = required.value;
        if (delivered < 1 || delivered > outputLength + 1) return const NativeBridgeResult(NativeOperationResult.failed);
        if (second == 7) {
          if (onStream == null) return const NativeBridgeResult(NativeOperationResult.failed);
          try {
            final decoded = jsonDecode(utf8.decode(output.asTypedList(delivered), allowMalformed: false));
            if (decoded is Map<String, Object?>) onStream(CompanionChatStreamSnapshot.fromBridgeJson(decoded));
          } on Object {
            // An invalid preview never takes ownership away from terminal/drain.
          }
          return const NativeBridgeResult(NativeOperationResult.pending);
        }
        if (second == 6) {
          if (onActivity == null) return const NativeBridgeResult(NativeOperationResult.failed);
          // Activity is observational. A malformed frame or an observer
          // exception cannot abandon the one owned poll/free lifecycle or
          // hide the eventual terminal result.
          try {
            final decoded = jsonDecode(utf8.decode(output.asTypedList(delivered), allowMalformed: false));
            if (decoded is Map<String, Object?>) onActivity(CompanionChatActivitySnapshot.fromBridgeJson(decoded));
          } on Object {
            // Drop this side-channel observation; continue polling terminal.
          }
          return const NativeBridgeResult(NativeOperationResult.pending);
        }
        final terminal = _resultKind(second);
        // Chat's public busy/unavailable/timeout/indeterminate terminals use
        // the ABI's failed result code. Decode the bounded public JSON for
        // that terminal too; a legacy failure with no valid JSON still stays
        // a plain failed result below.
        if (terminal != NativeOperationResult.ok &&
            terminal != NativeOperationResult.denied &&
            terminal != NativeOperationResult.failed) {
          return NativeBridgeResult(terminal);
        }
        final decoded = jsonDecode(utf8.decode(output.asTypedList(delivered), allowMalformed: false));
        if (decoded is! Map<String, Object?>) return const NativeBridgeResult(NativeOperationResult.failed);
        return NativeBridgeResult(terminal, decoded);
      } on FormatException {
        return const NativeBridgeResult(NativeOperationResult.failed);
      } finally {
        output.asTypedList(outputLength + 1).fillRange(0, outputLength + 1, 0);
        calloc.free(output);
      }
    } finally {
      calloc.free(required);
    }
  }

  @override
  Future<void> cancelActiveChat() async {
    final operation = _active;
    if (operation == null) return;
    _cancelOperation(operation);
  }

  void _cancelOperation(Pointer<_Operation> operation) {
    if (_active != operation || _activeCancelRequested) return;
    _activeCancelRequested = true;
    // Native cancel blocks until its transport worker drains. It deliberately
    // does not free this opaque operation; _pollUntilTerminal remains owner.
    _operationCancel(operation);
  }

  @override
  Future<void> dispose() {
    return _disposeFuture ??= _disposeSafely();
  }

  Future<void> _disposeSafely() async {
    _closing = true;
    final operation = _active;
    final activeFinished = _activeFinished;
    if (operation != null) {
      // Disposal is generic for pair, reconnect, and chat. Retain the poll
      // completion before cancellation: native drain can let poll clear the
      // mutable field before this async continuation resumes.
      _cancelOperation(operation);
      // The native handle is drained by the normal polling owner before the
      // bridge itself is released; cancellation must not race a worker thread.
      if (activeFinished != null) await activeFinished.future;
    }
    if (_bridge != nullptr) {
      _bridgeFree(_bridge);
      _bridge = nullptr;
    }
  }

  void _requireLive() {
    if (_closing || _bridge == nullptr) throw StateError('companion bridge is closed');
  }
}

_ChatStartV2Dart? _lookupChatStartV2(DynamicLibrary library) { try { return library.lookupFunction<_ChatStartV2Native, _ChatStartV2Dart>('neoth_companion_chat_start_v2'); } on ArgumentError { return null; } }
_PollV2Dart? _lookupPollV2(DynamicLibrary library) { try { return library.lookupFunction<_PollV2Native, _PollV2Dart>('neoth_companion_operation_poll_v2'); } on ArgumentError { return null; } }

NativeOperationResult _resultKind(int raw) => switch (raw) {
      0 => NativeOperationResult.pending,
      1 => NativeOperationResult.ok,
      2 => NativeOperationResult.denied,
      3 => NativeOperationResult.failed,
      4 => NativeOperationResult.cancelled,
      _ => NativeOperationResult.failed,
    };

_ChatStartV2Dart? _lookupChatStartV3(DynamicLibrary library) { try { return library.lookupFunction<_ChatStartV2Native, _ChatStartV2Dart>('neoth_companion_chat_start_v3'); } on ArgumentError { return null; } }
_PollV2Dart? _lookupPollV3(DynamicLibrary library) { try { return library.lookupFunction<_PollV2Native, _PollV2Dart>('neoth_companion_operation_poll_v3'); } on ArgumentError { return null; } }
