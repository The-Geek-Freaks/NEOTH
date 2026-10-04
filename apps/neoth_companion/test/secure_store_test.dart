import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:neoth_companion/models.dart';
import 'package:neoth_companion/secure_store.dart';

void main() {
  test('a partial enrollment is cleared without replacing the device secret, then a complete enrollment round-trips', () async {
    FlutterSecureStorage.setMockInitialValues(<String, String>{
      'neoth_companion.device_secret.v1': _secretHex,
      'neoth_companion.revision.v3': '3',
      'neoth_companion.scope.v3': 'companion.status.read',
      'neoth_companion.reconnect.v3': '{"schema_version":3}',
    });
    const storage = FlutterSecureStorage();
    final store = SecureCompanionStore(storage);

    expect(await store.loadEnrollment(), isNull);
    expect(await storage.readAll(), <String, String>{
      'neoth_companion.device_secret.v1': _secretHex,
    });
    expect(await store.loadOrCreateDeviceSecret(), orderedEquals(List<int>.filled(32, 0xaa)));

    await store.saveEnrollment(_enrollment);
    final restored = await store.loadEnrollment();
    expect(restored?.deviceId, _deviceId);
    expect(restored?.revision, 3);
    expect(restored?.grantedScope, 'companion.status.read');
    expect(restored?.reconnectDescriptor, _enrollment.reconnectDescriptor);
    expect(await store.loadOrCreateDeviceSecret(), orderedEquals(List<int>.filled(32, 0xaa)));
  });
}

const _secretHex = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const _deviceId = '7fb8ae0f-9e36-4a64-83e2-972dff9af880';
const _enrollment = EnrollmentAccepted(
  deviceId: _deviceId,
  revision: 3,
  grantedScope: 'companion.status.read',
  reconnectDescriptor: <String, Object?>{
    'schema_version': 3,
    'carrier': 'peeroxide-hyperswarm-v3',
    'rendezvous_topic_hex': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'daemon_noise_public_key_hex': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'descriptor_generation': 1,
  },
);
