import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:neoth_companion/companion_controller.dart';
import 'package:neoth_companion/models.dart';
import 'package:neoth_companion/native_bridge.dart';
import 'package:neoth_companion/secure_store.dart';

void main() {
  group('CompanionController', () {
    test('persists a public enrollment only after a real accepted bridge frame', () async {
      final store = _MemoryStore();
      final bridge = _FakeBridge(pairResult: _acceptedResult());
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      await controller.pair(_invite, 'Pixel');

      expect(store.enrollment?.deviceId, _deviceId);
      expect(store.enrollment?.reconnectDescriptor['carrier'], 'peeroxide-hyperswarm-v3');
      expect(controller.state, CompanionViewState.offline);
      expect(bridge.pairCalls, 1);
    });

    test('denied pairing never stores a descriptor or silently retries', () async {
      final store = _MemoryStore();
      final bridge = _FakeBridge(pairResult: _deniedResult('unknown_device'));
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.pair(_invite, 'Pixel');

      expect(store.enrollment, isNull);
      expect(controller.state, CompanionViewState.denied);
      expect(bridge.pairCalls, 1);
    });

    test('restored enrollment reaches the real status state only for its same device id', () async {
      final store = _MemoryStore(enrollment: _accepted());
      final bridge = _FakeBridge(reconnectResult: _statusResult());
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      await controller.refresh();

      expect(controller.state, CompanionViewState.ready);
      expect(controller.status?.deviceId, _deviceId);
      expect(bridge.reconnectCalls, 1);
    });

    test('unknown active-turn inventory remains unavailable instead of becoming empty', () async {
      final store = _MemoryStore(enrollment: _accepted());
      final bridge = _FakeBridge(reconnectResult: _statusWithUnavailableTurns());
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      await controller.refresh();

      expect(controller.state, CompanionViewState.ready);
      expect(controller.status?.activeTurns, isNull);
    });

    test('revocation stays visible and preserves the protected local identity until user action', () async {
      final store = _MemoryStore(enrollment: _accepted());
      final bridge = _FakeBridge(reconnectResult: _deniedResult('revoked'));
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      await controller.refresh();

      expect(controller.state, CompanionViewState.revoked);
      expect(store.enrollment?.deviceId, _deviceId);
      expect(bridge.reconnectCalls, 1);
    });

    test('lifecycle disposal asks the owned native bridge to cancel and drain', () async {
      final store = _MemoryStore();
      final bridge = _FakeBridge();
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      controller.dispose();
      await Future<void>.microtask(() {});

      expect(bridge.disposeCalls, 1);
    });
  });
}

const _deviceId = '7fb8ae0f-9e36-4a64-83e2-972dff9af880';
const _invite = 'neoth://companion/pair?v=3&topic=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&psk=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&server_pk=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc&ttl=60';

EnrollmentAccepted _accepted() => EnrollmentAccepted(
      deviceId: _deviceId,
      revision: 1,
      grantedScope: 'status_read',
      reconnectDescriptor: const <String, Object?>{
        'schema_version': 3,
        'carrier': 'peeroxide-hyperswarm-v3',
        'rendezvous_topic': 'public',
        'daemon_noise_public_key': 'public',
        'descriptor_generation': 1,
      },
    );

NativeBridgeResult _acceptedResult() => NativeBridgeResult(NativeOperationResult.ok, <String, Object?>{
      'type': 'enrollment_accepted',
      'body': <String, Object?>{
        'schema_version': 3,
        'device_id': _deviceId,
        'revision': 1,
        'granted_scope': 'status_read',
        'reconnect': _accepted().reconnectDescriptor,
      },
    });

NativeBridgeResult _statusResult() => NativeBridgeResult(NativeOperationResult.ok, <String, Object?>{
      'type': 'status_snapshot',
      'body': <String, Object?>{
        'schema_version': 3,
        'device_id': _deviceId,
        'daemon_boot_id': 'boot-a',
        'readiness': 'ready',
        'observed_at_unix': 1700000000,
        'active_turns': const <Object?>[],
      },
    });

NativeBridgeResult _statusWithUnavailableTurns() => NativeBridgeResult(NativeOperationResult.ok, <String, Object?>{
      'type': 'status_snapshot',
      'body': <String, Object?>{
        'schema_version': 3,
        'device_id': _deviceId,
        'daemon_boot_id': 'boot-a',
        'readiness': 'ready',
        'observed_at_unix': 1700000000,
        'active_turns': null,
      },
    });

NativeBridgeResult _deniedResult(String code) => NativeBridgeResult(NativeOperationResult.denied, <String, Object?>{
      'type': 'denied',
      'body': <String, Object?>{'schema_version': 3, 'code': code},
    });

class _MemoryStore implements CompanionStore {
  _MemoryStore({this.enrollment});
  EnrollmentAccepted? enrollment;
  Uint8List secret = Uint8List.fromList(List<int>.filled(32, 9));

  @override
  Future<void> clearEnrollment() async => enrollment = null;
  @override
  Future<EnrollmentAccepted?> loadEnrollment() async => enrollment;
  @override
  Future<Uint8List> loadOrCreateDeviceSecret() async => Uint8List.fromList(secret);
  @override
  Future<void> saveEnrollment(EnrollmentAccepted value) async => enrollment = value;
}

class _FakeBridge implements NativeBridge {
  _FakeBridge({this.pairResult, this.reconnectResult});
  NativeBridgeResult? pairResult;
  NativeBridgeResult? reconnectResult;
  int pairCalls = 0;
  int reconnectCalls = 0;
  int disposeCalls = 0;

  @override
  Future<void> dispose() async => disposeCalls++;
  @override
  Future<NativeBridgeResult> pair(String inviteUrl, String label) async {
    pairCalls++;
    return pairResult ?? const NativeBridgeResult(NativeOperationResult.failed);
  }
  @override
  Future<NativeBridgeResult> reconnect(String descriptorJson, String deviceId) async {
    reconnectCalls++;
    return reconnectResult ?? const NativeBridgeResult(NativeOperationResult.failed);
  }
}
