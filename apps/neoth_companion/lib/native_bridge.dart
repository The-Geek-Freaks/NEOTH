import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bridge_input.dart';

enum NativeOperationResult { pending, ok, denied, failed, cancelled }

class NativeBridgeResult {
  const NativeBridgeResult(this.kind, [this.publicJson]);
  final NativeOperationResult kind;
  final Map<String, Object?>? publicJson;
}

abstract interface class NativeBridge {
  Future<NativeBridgeResult> pair(String inviteUrl, String label);
  Future<NativeBridgeResult> reconnect(String descriptorJson, String deviceId);
  Future<void> dispose();
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
typedef _PollNative = Int32 Function(Pointer<_Operation>, Pointer<Uint8>, IntPtr, Pointer<IntPtr>);
typedef _PollDart = int Function(Pointer<_Operation>, Pointer<Uint8>, int, Pointer<IntPtr>);
typedef _OperationVoidNative = Void Function(Pointer<_Operation>);
typedef _OperationVoidDart = void Function(Pointer<_Operation>);

/// Owns one Rust bridge allocation and exactly one in-flight operation.  The
/// opaque native bridge derives the signing and Noise identities from the
/// protected seed; neither private material nor invite data crosses back.
class FfiNativeBridge implements NativeBridge {
  FfiNativeBridge._(DynamicLibrary library, Uint8List seed)
      : _bridgeFree = library.lookupFunction<_BridgeFreeNative, _BridgeFreeDart>('neoth_companion_bridge_free'),
        _pairStart = library.lookupFunction<_PairStartNative, _PairStartDart>('neoth_companion_pair_start'),
        _reconnectStart = library.lookupFunction<_ReconnectStartNative, _ReconnectStartDart>('neoth_companion_reconnect_start'),
        _poll = library.lookupFunction<_PollNative, _PollDart>('neoth_companion_operation_poll'),
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
  final _PollDart _poll;
  final _OperationVoidDart _operationCancel;
  final _OperationVoidDart _operationFree;
  Pointer<_Bridge> _bridge;
  Pointer<_Operation>? _active;
  Completer<void>? _activeFinished;
  Future<void>? _disposeFuture;
  bool _closing = false;

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

  Future<NativeBridgeResult> _pollUntilTerminal(Pointer<_Operation> operation) async {
    try {
      while (_active == operation) {
        final result = _readPoll(operation);
        if (result.kind != NativeOperationResult.pending) return result;
        await Future<void>.delayed(const Duration(milliseconds: 125));
      }
      return const NativeBridgeResult(NativeOperationResult.cancelled);
    } finally {
      if (_active == operation) _active = null;
      _operationFree(operation);
      _activeFinished?.complete();
      _activeFinished = null;
    }
  }

  NativeBridgeResult _readPoll(Pointer<_Operation> operation) {
    final required = calloc<IntPtr>();
    try {
      final first = _poll(operation, nullptr, 0, required);
      if (first == 0) return const NativeBridgeResult(NativeOperationResult.pending);
      // ABI r1 returned 1 for a probe whose buffer was absent; ABI r2 uses 5.
      // Both spellings are accepted only for this size-discovery call, so a
      // deployed r1 bridge cannot turn into a false terminal success.
      if ((first != 1 && first != 5) || required.value == 0 || required.value > 8192) {
        return NativeBridgeResult(_resultKind(first));
      }
      final output = calloc<Uint8>(required.value + 1);
      try {
        final second = _poll(operation, output, required.value + 1, required);
        final terminal = _resultKind(second);
        if (terminal != NativeOperationResult.ok && terminal != NativeOperationResult.denied) return NativeBridgeResult(terminal);
        final decoded = jsonDecode(utf8.decode(output.asTypedList(required.value), allowMalformed: false));
        if (decoded is! Map<String, Object?>) return const NativeBridgeResult(NativeOperationResult.failed);
        return NativeBridgeResult(terminal, decoded);
      } on FormatException {
        return const NativeBridgeResult(NativeOperationResult.failed);
      } finally {
        output.asTypedList(required.value + 1).fillRange(0, required.value + 1, 0);
        calloc.free(output);
      }
    } finally {
      calloc.free(required);
    }
  }

  @override
  Future<void> dispose() {
    return _disposeFuture ??= _disposeSafely();
  }

  Future<void> _disposeSafely() async {
    _closing = true;
    final operation = _active;
    if (operation != null) {
      _operationCancel(operation);
      // The native handle is drained by the normal polling owner before the
      // bridge itself is released; cancellation must not race a worker thread.
      await _activeFinished!.future;
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

NativeOperationResult _resultKind(int raw) => switch (raw) {
      0 => NativeOperationResult.pending,
      1 => NativeOperationResult.ok,
      2 => NativeOperationResult.denied,
      3 => NativeOperationResult.failed,
      4 => NativeOperationResult.cancelled,
      _ => NativeOperationResult.failed,
    };
